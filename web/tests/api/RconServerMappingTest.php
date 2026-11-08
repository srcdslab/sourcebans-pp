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
        ];
    }

    /** @param array<string, mixed> $params */
    #[DataProvider('rconActions')]
    public function testUnmappedAdminIsRefused(string $action, array $params): void
    {
        $this->loginAsUnmappedBanAdmin();
        $this->assertEnvelopeError($this->api($action, $params), 'forbidden');
    }
}
