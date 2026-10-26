<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * `web/updater/data/816.php` (upstream #1600): Steam Networking (SDR)
 * clients reach the server under a shared 169.254.x.x placeholder, so
 * older plugins stored it as if it were the player's IP. The migration
 * turns SDR IP bans with a real SteamID into SteamID bans and clears
 * every stored placeholder, without touching real addresses.
 */
final class Updater816SteamNetworkingIpTest extends ApiTestCase
{
    private function runMigration(): bool
    {
        $ctx = new class($GLOBALS['PDO']) {
            public function __construct(public \Database $dbs) {}

            public function run(string $path): mixed
            {
                return require $path;
            }
        };

        return (bool) $ctx->run(ROOT . 'updater/data/816.php');
    }

    private function insertBan(int $type, ?string $ip, string $authid, string $adminIp = ''): int
    {
        $pdo = Fixture::rawPdo();
        $stmt = $pdo->prepare(
            'INSERT INTO `' . DB_PREFIX . '_bans` (type, ip, authid, name, created, ends, length, reason, aid, adminIp)'
            . " VALUES (?, ?, ?, 'p', 0, 0, 0, 'r', 0, ?)"
        );
        $stmt->execute([$type, $ip, $authid, $adminIp]);

        return (int) $pdo->lastInsertId();
    }

    /** @return array<string, mixed> */
    private function ban(int $bid): array
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT type, ip, authid, adminIp FROM `' . DB_PREFIX . '_bans` WHERE bid = ?');
        $stmt->execute([$bid]);

        return (array) $stmt->fetch(\PDO::FETCH_ASSOC);
    }

    public function testCleansPlaceholderAddressesAndIsIdempotent(): void
    {
        $sdrIpBan    = $this->insertBan(1, '169.254.12.34', 'STEAM_0:1:1234');
        $sdrNoSteam  = $this->insertBan(1, '169.254.12.35', '');
        $steamBan    = $this->insertBan(0, '169.254.1.1', 'STEAM_0:0:42', '169.254.9.9');
        $realIpBan   = $this->insertBan(1, '203.0.113.7', 'STEAM_0:0:7', '198.51.100.1');

        $pdo = Fixture::rawPdo();
        $pdo->exec('INSERT INTO `' . DB_PREFIX . "_comms` (authid, name, created, ends, length, reason, aid, adminIp, type) VALUES ('STEAM_0:0:5', 'p', 0, 0, 0, 'r', 0, '169.254.3.3', 1)");
        $pdo->exec('INSERT INTO `' . DB_PREFIX . "_submissions` (submitted, ModID, SteamId, name, email, reason, ip, sip) VALUES (0, 0, 'STEAM_0:0:6', 'p', '', 'r', '169.254.4.4', '169.254.5.5')");

        $this->assertTrue($this->runMigration(), 'First run should succeed.');

        $this->assertSame(['type' => 0, 'ip' => null, 'authid' => 'STEAM_0:1:1234', 'adminIp' => ''],
            $this->normalise($this->ban($sdrIpBan)), 'SDR IP ban with a SteamID becomes a SteamID ban.');
        $this->assertSame(['type' => 1, 'ip' => null, 'authid' => '', 'adminIp' => ''],
            $this->normalise($this->ban($sdrNoSteam)), 'SDR IP ban without a SteamID only loses the placeholder.');
        $this->assertSame(['type' => 0, 'ip' => null, 'authid' => 'STEAM_0:0:42', 'adminIp' => ''],
            $this->normalise($this->ban($steamBan)), 'Placeholder ip and adminIp are cleared.');
        $this->assertSame(['type' => 1, 'ip' => '203.0.113.7', 'authid' => 'STEAM_0:0:7', 'adminIp' => '198.51.100.1'],
            $this->normalise($this->ban($realIpBan)), 'Real addresses are left alone.');

        $this->assertSame('', (string) $pdo->query('SELECT adminIp FROM `' . DB_PREFIX . "_comms` WHERE authid = 'STEAM_0:0:5'")->fetchColumn());
        $sub = $pdo->query('SELECT ip, sip FROM `' . DB_PREFIX . "_submissions` WHERE SteamId = 'STEAM_0:0:6'")->fetch(\PDO::FETCH_ASSOC);
        $this->assertSame(['ip' => '', 'sip' => null], $sub);

        $this->assertTrue($this->runMigration(), 'Second run must be a no-op.');
        $this->assertSame(['type' => 1, 'ip' => '203.0.113.7', 'authid' => 'STEAM_0:0:7', 'adminIp' => '198.51.100.1'],
            $this->normalise($this->ban($realIpBan)));
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    private function normalise(array $row): array
    {
        $row['type'] = (int) $row['type'];

        return $row;
    }
}
