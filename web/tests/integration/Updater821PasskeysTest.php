<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #108: `web/updater/data/821.php` creates the passkey tables. Same
 * harness as Updater820TwoFactorTest.
 */
final class Updater821PasskeysTest extends ApiTestCase
{
    private const TABLES = ['admin_passkeys', 'webauthn_challenges'];

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
        return (bool) $ctx->run(ROOT . 'updater/data/821.php');
    }

    public function testFreshSchemaMatchesAndReRunsAreNoOps(): void
    {
        foreach (self::TABLES as $t) {
            $this->assertTrue($this->tableExists($t), "struc.sql must create $t.");
        }
        $this->assertTrue($this->runMigration());
        $this->assertTrue($this->runMigration());
    }

    public function testMigrationUpgradesA820Schema(): void
    {
        foreach (self::TABLES as $t) {
            Fixture::rawPdo()->exec('DROP TABLE `' . DB_PREFIX . '_' . $t . '`');
        }

        $this->assertTrue($this->runMigration());

        foreach (self::TABLES as $t) {
            $this->assertTrue($this->tableExists($t));
        }
    }

    public function testMigrationIsRegisteredInStoreJson(): void
    {
        $store = json_decode((string) file_get_contents(ROOT . 'updater/store.json'), true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame('821.php', $store['821'] ?? null);
    }
}
