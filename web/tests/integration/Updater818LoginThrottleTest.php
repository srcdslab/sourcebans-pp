<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #97: `web/updater/data/818.php` creates `:prefix_login_throttle`. Same
 * harness as Updater801LockoutColumnsTest.
 */
final class Updater818LoginThrottleTest extends ApiTestCase
{
    private function tableExists(): bool
    {
        $stmt = Fixture::rawPdo()->prepare(
            'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?'
        );
        $stmt->execute([DB_NAME, DB_PREFIX . '_login_throttle']);

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

        return (bool) $ctx->run(ROOT . 'updater/data/818.php');
    }

    public function testFreshSchemaAlreadyHasTheTableAndMigrationIsIdempotent(): void
    {
        $this->assertTrue($this->tableExists(), 'struc.sql must create login_throttle.');
        $this->assertTrue($this->runMigration());
        $this->assertTrue($this->runMigration());
    }

    public function testMigrationCreatesTheTableOnAnUpgradedSchema(): void
    {
        Fixture::rawPdo()->exec('DROP TABLE `' . DB_PREFIX . '_login_throttle`');
        $this->assertFalse($this->tableExists());

        $this->assertTrue($this->runMigration());

        $this->assertTrue($this->tableExists());
    }

    public function testMigrationIsRegisteredInStoreJson(): void
    {
        $store = json_decode((string) file_get_contents(ROOT . 'updater/store.json'), true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame('818.php', $store['818'] ?? null);
    }
}
