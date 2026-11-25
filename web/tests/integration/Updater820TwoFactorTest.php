<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #107: `web/updater/data/820.php` creates the two-factor tables and the
 * `auth.2fa.require` setting (off). Same harness as Updater819AuthThrottleTest.
 */
final class Updater820TwoFactorTest extends ApiTestCase
{
    private const TABLES = ['admin_totp', 'admin_recovery_codes', 'auth_pending'];

    private function tableExists(string $table): bool
    {
        $stmt = Fixture::rawPdo()->prepare(
            'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?'
        );
        $stmt->execute([DB_NAME, DB_PREFIX . '_' . $table]);
        return (int) $stmt->fetchColumn() > 0;
    }

    private function setting(): ?string
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT value FROM `' . DB_PREFIX . "_settings` WHERE setting = 'auth.2fa.require'");
        $stmt->execute();
        $value = $stmt->fetchColumn();
        return $value === false ? null : (string) $value;
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
        return (bool) $ctx->run(ROOT . 'updater/data/820.php');
    }

    public function testFreshSchemaMatchesTheMigrationAndReRunsAreNoOps(): void
    {
        foreach (self::TABLES as $t) {
            $this->assertTrue($this->tableExists($t), "struc.sql must create $t.");
        }
        $this->assertSame('off', $this->setting(), 'data.sql seeds the setting off.');
        $this->assertTrue($this->runMigration());
        $this->assertTrue($this->runMigration());
    }

    public function testMigrationUpgradesA819SchemaAndKeepsAnExistingSetting(): void
    {
        $pdo = Fixture::rawPdo();
        foreach (self::TABLES as $t) {
            $pdo->exec('DROP TABLE `' . DB_PREFIX . '_' . $t . '`');
        }
        $pdo->exec('DELETE FROM `' . DB_PREFIX . "_settings` WHERE setting = 'auth.2fa.require'");

        $this->assertTrue($this->runMigration());

        foreach (self::TABLES as $t) {
            $this->assertTrue($this->tableExists($t));
        }
        $this->assertSame('off', $this->setting());

        $pdo->exec('UPDATE `' . DB_PREFIX . "_settings` SET value = 'all' WHERE setting = 'auth.2fa.require'");
        $this->assertTrue($this->runMigration());
        $this->assertSame('all', $this->setting(), 'A re-run must not reset the setting.');
    }

    public function testMigrationIsRegisteredInStoreJson(): void
    {
        $store = json_decode((string) file_get_contents(ROOT . 'updater/store.json'), true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame('820.php', $store['820'] ?? null);
    }
}
