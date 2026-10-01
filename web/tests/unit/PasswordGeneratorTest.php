<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sbpp\Security\PasswordGenerator;

/**
 * Contract pins for `Sbpp\Security\PasswordGenerator`: length clamping,
 * per-set guarantees, ambiguous-character exclusion, and the settings
 * keys staying in sync between the class, data.sql, and the updater
 * migration that backfills upgraded installs.
 */
final class PasswordGeneratorTest extends TestCase
{
    /**
     * @return array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}
     */
    private static function opts(array $overrides = []): array
    {
        /** @var array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool} */
        return array_merge([
            'length'            => 32,
            'lowercase'         => true,
            'uppercase'         => true,
            'digits'            => true,
            'symbols'           => true,
            'exclude_ambiguous' => false,
        ], $overrides);
    }

    public function testGeneratesRequestedLength(): void
    {
        foreach ([PasswordGenerator::minLength(), 20, 64, PasswordGenerator::MAX_LENGTH] as $len) {
            $this->assertSame($len, strlen(PasswordGenerator::generate(self::opts(['length' => $len]))));
        }
    }

    public function testLengthIsClampedToBounds(): void
    {
        $short = PasswordGenerator::generate(self::opts(['length' => 1]));
        $this->assertSame(PasswordGenerator::minLength(), strlen($short));

        $long = PasswordGenerator::generate(self::opts(['length' => 10_000]));
        $this->assertSame(PasswordGenerator::MAX_LENGTH, strlen($long));
    }

    public function testMinLengthNeverDropsBelowFloorOrPanelMinimum(): void
    {
        $this->assertGreaterThanOrEqual(PasswordGenerator::MIN_LENGTH, PasswordGenerator::minLength());
        if (defined('MIN_PASS_LENGTH')) {
            $this->assertGreaterThanOrEqual(
                min(PasswordGenerator::MAX_LENGTH, (int) MIN_PASS_LENGTH),
                PasswordGenerator::minLength(),
            );
        }
    }

    public function testEveryEnabledSetIsRepresented(): void
    {
        // Minimum length with all four sets: the per-set guarantee is
        // what makes this pass every time, not luck.
        for ($i = 0; $i < 200; $i++) {
            $pw = PasswordGenerator::generate(self::opts(['length' => PasswordGenerator::minLength()]));
            $this->assertMatchesRegularExpression('/[a-z]/', $pw);
            $this->assertMatchesRegularExpression('/[A-Z]/', $pw);
            $this->assertMatchesRegularExpression('/[0-9]/', $pw);
            $this->assertMatchesRegularExpression(
                '/[' . preg_quote(PasswordGenerator::SYMBOLS, '/') . ']/',
                $pw,
            );
        }
    }

    public function testOnlyEnabledSetsAreUsed(): void
    {
        $digitsOnly = PasswordGenerator::generate(self::opts([
            'lowercase' => false, 'uppercase' => false, 'symbols' => false,
        ]));
        $this->assertMatchesRegularExpression('/^[0-9]+$/', $digitsOnly);

        $noSymbols = PasswordGenerator::generate(self::opts(['symbols' => false, 'length' => 128]));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]+$/', $noSymbols);
    }

    public function testExcludeAmbiguousDropsLookAlikes(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $pw = PasswordGenerator::generate(self::opts(['length' => 128, 'exclude_ambiguous' => true]));
            $this->assertSame(
                strlen($pw),
                strcspn($pw, PasswordGenerator::AMBIGUOUS),
                "look-alike character in '{$pw}'",
            );
        }
    }

    public function testSymbolsAvoidConsoleUnsafeCharacters(): void
    {
        foreach (['"', "'", '\\', ';', ' ', '`'] as $bad) {
            $this->assertStringNotContainsString($bad, PasswordGenerator::SYMBOLS);
        }
    }

    public function testNoCharacterSetIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PasswordGenerator::generate(self::opts([
            'lowercase' => false, 'uppercase' => false, 'digits' => false, 'symbols' => false,
        ]));
    }

    public function testResolveAcceptsFormStyleBooleans(): void
    {
        $opts = PasswordGenerator::resolve(
            ['length' => '24', 'lowercase' => '1', 'uppercase' => 'false', 'digits' => 0, 'symbols' => 'on'],
            self::opts(),
        );
        $this->assertSame(24, $opts['length']);
        $this->assertTrue($opts['lowercase']);
        $this->assertFalse($opts['uppercase']);
        $this->assertFalse($opts['digits']);
        $this->assertTrue($opts['symbols']);
        $this->assertFalse($opts['exclude_ambiguous'], 'unspecified options keep the base value');
    }

    public function testOutputIsNotDeterministic(): void
    {
        $seen = [];
        for ($i = 0; $i < 20; $i++) {
            $seen[PasswordGenerator::generate(self::opts())] = true;
        }
        $this->assertCount(20, $seen);
    }

    /**
     * Fresh installs seed from data.sql; upgrades run 813.php. Both
     * must carry every key the class reads, or one install path
     * silently falls back to the built-in defaults.
     */
    public function testSettingsKeysAreSeededOnBothInstallPaths(): void
    {
        $root = dirname(__DIR__, 2);
        $dataSql = (string) file_get_contents($root . '/install/includes/sql/data.sql');
        $migration = (string) file_get_contents($root . '/updater/data/813.php');
        $store = (string) file_get_contents($root . '/updater/store.json');

        $this->assertStringContainsString('"813": "813.php"', $store);
        foreach (PasswordGenerator::SETTINGS as $key) {
            $this->assertMatchesRegularExpression("/\\('" . preg_quote($key, '/') . "', '[^']*'\\)/", $dataSql, "data.sql misses {$key}");
            $this->assertMatchesRegularExpression("/\\('" . preg_quote($key, '/') . "', '[^']*'\\)/", $migration, "813.php misses {$key}");

            preg_match("/\\('" . preg_quote($key, '/') . "', '([^']*)'\\)/", $dataSql, $a);
            preg_match("/\\('" . preg_quote($key, '/') . "', '([^']*)'\\)/", $migration, $b);
            $this->assertSame($a[1] ?? null, $b[1] ?? null, "default for {$key} differs between data.sql and 813.php");
        }
    }
}
