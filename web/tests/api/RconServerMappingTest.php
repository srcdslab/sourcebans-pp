<?php

namespace Sbpp\Tests\Api;

use PHPUnit\Framework\Attributes\DataProvider;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * Security audit 2026-11: bans.paste, comms.paste, bans.kick_player and
 * kickit.kick_player (mode=kick) ran RCON on any server id. Like
 * servers.send_rcon and bans.send_message, they now require the caller to
 * be an Owner or mapped to that server. The refusal happens before any
 * RCON connection, so these tests need no game server.
 */
final class RconServerMappingTest extends ApiTestCase
{
    private function loginAsUnmappedBanAdmin(): void
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_admins` (user, authid, password, gid, email, validate, extraflags, immunity)
             VALUES (?, ?, ?, -1, ?, NULL, ?, 0)',
            DB_PREFIX,
        ))->execute(['unmapped', 'STEAM_0:0:5150', password_hash('x', PASSWORD_BCRYPT), 'unmapped@example.test', ADMIN_ADD_BAN]);
        $this->loginAs((int) $pdo->lastInsertId());
    }

    /** @return array<string, array{string, array<string, mixed>}> */
    public static function rconActions(): array
    {
        return [
            'bans.paste'          => ['bans.paste', ['sid' => 1, 'name' => 'x']],
            'comms.paste'         => ['comms.paste', ['sid' => 1, 'name' => 'x']],
            'bans.kick_player'    => ['bans.kick_player', ['sid' => 1, 'name' => 'x']],
            'kickit.kick_player'  => ['kickit.kick_player', ['sid' => 1, 'check' => 'STEAM_0:1:123', 'type' => 0, 'mode' => 'kick']],
            'blockit.block_player' => ['blockit.block_player', ['sid' => 1, 'check' => 'STEAM_0:1:123', 'type' => 1, 'length' => 0]],
        ];
    }

    /** @param array<string, mixed> $params */
    #[DataProvider('rconActions')]
    public function testUnmappedAdminIsRefused(string $action, array $params): void
    {
        $this->loginAsUnmappedBanAdmin();
        $this->assertEnvelopeError($this->api($action, $params), 'forbidden');
    }

    public function testBanModeWithoutAnActiveBanIsRefused(): void
    {
        // `mode` is client-controlled: mode=ban must not be a way around
        // the per-server mapping when no ban exists for the target.
        $this->loginAsUnmappedBanAdmin();
        $env = $this->api('kickit.kick_player', ['sid' => 1, 'check' => 'STEAM_0:1:123', 'type' => 0, 'mode' => 'ban']);
        $this->assertEnvelopeError($env, 'forbidden');
    }

    public function testBanModeFansOutForAnActivelyBannedTarget(): void
    {
        Fixture::rawPdo()->prepare(sprintf(
            'INSERT INTO `%s_bans` (created, type, ip, authid, name, ends, length, reason, aid, adminIp)
             VALUES (UNIX_TIMESTAMP(), 0, \'\', ?, ?, 0, 0, ?, ?, \'127.0.0.1\')',
            DB_PREFIX,
        ))->execute(['STEAM_1:1:123', 'cheater', 'aimbot', Fixture::adminAid()]);

        $this->loginAsUnmappedBanAdmin();
        $env = $this->api('kickit.kick_player', ['sid' => 1, 'check' => 'STEAM_0:1:123', 'type' => 0, 'mode' => 'ban']);

        // Not refused: the call reaches the RCON step (no game server in
        // the test stack, so it reports no_connect).
        $this->assertTrue($env['ok'], json_encode($env));
    }

    private function insertComm(int $type, string $authid): void
    {
        Fixture::rawPdo()->prepare(sprintf(
            'INSERT INTO `%s_comms` (created, type, authid, name, ends, length, reason, aid, adminIp)
             VALUES (UNIX_TIMESTAMP(), ?, ?, ?, 0, 0, ?, ?, \'127.0.0.1\')',
            DB_PREFIX,
        ))->execute([$type, $authid, 'chatter', 'spam', Fixture::adminAid()]);
    }

    public function testBlockFanOutGoesThroughForAnActivelyBlockedTarget(): void
    {
        // The post-comms.add fan-out applies a global block on every
        // server, like kickit's mode=ban.
        $this->insertComm(1, 'STEAM_1:1:123');
        $this->loginAsUnmappedBanAdmin();

        $env = $this->api('blockit.block_player', ['sid' => 1, 'check' => 'STEAM_0:1:123', 'type' => 1, 'length' => 0]);

        $this->assertTrue($env['ok'], json_encode($env));
    }

    public function testBlockOfAnotherTypeIsRefused(): void
    {
        // An active mute does not authorise a gag on an unmapped server.
        $this->insertComm(1, 'STEAM_0:1:123');
        $this->loginAsUnmappedBanAdmin();

        $env = $this->api('blockit.block_player', ['sid' => 1, 'check' => 'STEAM_0:1:123', 'type' => 2, 'length' => 0]);

        $this->assertEnvelopeError($env, 'forbidden');
    }

    public function testKickModeServerListFlagsUnmappedServersWithoutLogging(): void
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_servers` (sid, ip, port, rcon, modid, enabled) VALUES (1, \'10.0.0.1\', 27015, \'r\', 1, 1)',
            DB_PREFIX,
        ))->execute();
        $this->loginAsUnmappedBanAdmin();
        $logsBefore = (int) $pdo->query(sprintf('SELECT COUNT(*) FROM `%s_log`', DB_PREFIX))->fetchColumn();

        $kick = $this->api('kickit.load_servers', ['mode' => 'kick']);
        $ban  = $this->api('kickit.load_servers', []);

        // Kick mode marks the unmapped server so the iframe skips it
        // instead of calling kick_player and logging a Hacking Attempt.
        $this->assertFalse($kick['data']['servers'][0]['allowed']);
        $this->assertTrue($ban['data']['servers'][0]['allowed']);
        $this->assertSame($logsBefore, (int) $pdo->query(sprintf('SELECT COUNT(*) FROM `%s_log`', DB_PREFIX))->fetchColumn());
    }
}
