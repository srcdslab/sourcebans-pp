<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #106: `web/updater/data/819.php` creates `:prefix_auth_throttle`, drops
 * `:prefix_login_throttle` and clears the retired per-account lockout.
 * Same harness as Updater818LoginThrottleTest.
 */
final class Updater819AuthThrottleTest extends ApiTestCase
{
    private function tableExists(string $table): bool
    {
        $stmt = Fixture::rawPdo()->prepare(
            'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?'
        );
        $stmt->execute([DB_NAME, DB_PREFIX . '_' . $table]);

        return (int) $stmt->fetchColumn() > 0;
    }

    private function runMigration(): bool
    {
        $ctx = new class($GLOBALS['PDO']) {
            public function __construct(public \Database $dbs) {}

            public function run(string $path): mixed
            {
                return require $path;
            }
        };

        return (bool) $ctx->run(ROOT . 'updater/data/819.php');
    }

    public function testFreshSchemaAlreadyHasTheTableAndMigrationIsIdempotent(): void
    {
        $this->assertTrue($this->tableExists('auth_throttle'), 'struc.sql must create auth_throttle.');
        $this->assertTrue($this->runMigration());
        $this->assertTrue($this->runMigration());
        $this->assertTrue($this->tableExists('auth_throttle'));
    }

    public function testMigrationUpgradesA818Schema(): void
    {
        $pdo = Fixture::rawPdo();
        $pdo->exec('DROP TABLE `' . DB_PREFIX . '_auth_throttle`');
        $pdo->exec(
            'CREATE TABLE `' . DB_PREFIX . '_login_throttle` (`ip` varchar(32) NOT NULL, `attempts` int(10) UNSIGNED NOT NULL DEFAULT 0,'
            . ' `window_start` int(11) NOT NULL, PRIMARY KEY (`ip`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
        $pdo->prepare('UPDATE `' . DB_PREFIX . '_admins` SET attempts = 5, lockout_until = ? WHERE aid = ?')
            ->execute([date('Y-m-d H:i:s', time() + 600), Fixture::adminAid()]);

        $this->assertTrue($this->runMigration());

        $this->assertTrue($this->tableExists('auth_throttle'));
        $this->assertFalse($this->tableExists('login_throttle'));
        $admin = $this->row('admins', ['aid' => Fixture::adminAid()]);
        $this->assertSame(0, (int) $admin['attempts'], 'No account stays locked by the old rule.');
        $this->assertNull($admin['lockout_until']);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $this->assertSame('?', $env['redirect'] ?? null, 'Password sign-in works again after the updater.');
    }

    public function testMigrationIsRegisteredInStoreJson(): void
    {
        $store = json_decode((string) file_get_contents(ROOT . 'updater/store.json'), true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame('819.php', $store['819'] ?? null);
    }
}
