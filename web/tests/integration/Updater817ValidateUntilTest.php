<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #96: `web/updater/data/817.php` adds `:prefix_admins.validate_until`, the
 * password reset token deadline. Same harness as Updater801LockoutColumnsTest.
 */
final class Updater817ValidateUntilTest extends ApiTestCase
{
    private function columnExists(string $column): bool
    {
        $pdo = Fixture::rawPdo();
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS '
            . 'WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?'
        );
        $stmt->execute([DB_NAME, DB_PREFIX . '_admins', $column]);

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

        return (bool) $ctx->run(ROOT . 'updater/data/817.php');
    }

    public function testFreshSchemaAlreadyHasTheColumnAndMigrationIsIdempotent(): void
    {
        $this->assertTrue($this->columnExists('validate_until'), 'struc.sql must carry validate_until.');
        $this->assertTrue($this->runMigration(), 'First run should succeed.');
        $this->assertTrue($this->runMigration(), 'Second run must not fatal on duplicate column.');
    }

    public function testMigrationAddsTheColumnOnAnUpgradedSchema(): void
    {
        $table = DB_PREFIX . '_admins';
        Fixture::rawPdo()->exec("ALTER TABLE `{$table}` DROP COLUMN `validate_until`");
        $this->assertFalse($this->columnExists('validate_until'), 'Pre-condition: column dropped.');

        $this->assertTrue($this->runMigration());

        $this->assertTrue($this->columnExists('validate_until'), 'Migration must add validate_until.');
    }

    public function testMigrationIsRegisteredInStoreJson(): void
    {
        $store = json_decode((string) file_get_contents(ROOT . 'updater/store.json'), true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame('817.php', $store['817'] ?? null);
    }
}
