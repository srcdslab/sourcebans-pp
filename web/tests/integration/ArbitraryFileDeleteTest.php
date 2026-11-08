<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sbpp\Upload\UploadHandler;

/**
 * Security audit 2026-11: file names read back from the database (demo
 * `filename`, mod `icon`) were joined to an upload directory and passed
 * to unlink(). A tampered `did=../config.php` or `icon_hid=../../x` turned
 * that into an arbitrary file delete.
 *
 * Pins:
 *  - `UploadHandler::unlinkInside()` only deletes a regular file inside
 *    the given directory;
 *  - every unlink() of a stored name goes through it;
 *  - the edit-ban page validates `did` before storing it.
 */
final class ArbitraryFileDeleteTest extends TestCase
{
    private const WEB = __DIR__ . '/../../';

    private string $root;
    private string $uploads;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/sbpp-unlink-' . bin2hex(random_bytes(6));
        $this->uploads = $this->root . '/uploads';
        mkdir($this->uploads, 0777, true);
        file_put_contents($this->root . '/config.php', 'secret');
        file_put_contents($this->uploads . '/icon.png', 'png');
    }

    protected function tearDown(): void
    {
        foreach (['/uploads/icon.png', '/uploads/link.png', '/config.php'] as $f) {
            if (is_link($this->root . $f) || is_file($this->root . $f)) {
                unlink($this->root . $f);
            }
        }
        @rmdir($this->uploads);
        @rmdir($this->root);
    }

    /** @return array<string, array{string}> */
    public static function hostileNames(): array
    {
        return [
            'parent'          => ['../config.php'],
            'nested parent'   => ['x/../../config.php'],
            'absolute'        => ['/etc/passwd'],
            'backslash'       => ['..\\config.php'],
            'dot dot'         => ['..'],
            'hidden'          => ['.htaccess'],
            'nul byte'        => ["icon.png\0.txt"],
            'empty'           => [''],
        ];
    }

    #[DataProvider('hostileNames')]
    public function testUnsafeStoredNamesAreRejected(string $name): void
    {
        $this->assertFalse(UploadHandler::isSafeStoredName($name));
        $this->assertFalse(UploadHandler::unlinkInside($this->uploads, $name));
        $this->assertFileExists($this->root . '/config.php');
    }

    public function testDeletesAPlainFileInsideTheDirectory(): void
    {
        $this->assertTrue(UploadHandler::isSafeStoredName('icon.png'));
        $this->assertTrue(UploadHandler::unlinkInside($this->uploads, 'icon.png'));
        $this->assertFileDoesNotExist($this->uploads . '/icon.png');
    }

    public function testRefusesASymlinkPointingOutside(): void
    {
        symlink($this->root . '/config.php', $this->uploads . '/link.png');
        $this->assertFalse(UploadHandler::unlinkInside($this->uploads, 'link.png'));
        $this->assertFileExists($this->root . '/config.php');
    }

    public function testNoRawUnlinkOfAStoredNameRemains(): void
    {
        foreach ([
            'pages/page.banlist.php',
            'pages/admin.edit.ban.php',
            'pages/admin.edit.mod.php',
            'api/handlers/mods.php',
        ] as $file) {
            $src = php_strip_whitespace(self::WEB . $file);
            $this->assertDoesNotMatchRegularExpression(
                '/unlink\(\s*SB_(DEMOS|ICONS|MAPS)/',
                $src,
                "$file must delete stored files through UploadHandler::unlinkInside()",
            );
            $this->assertStringContainsString('UploadHandler::unlinkInside(', $src, $file);
        }
    }

    public function testEditBanValidatesDemoReferenceBeforeStoringIt(): void
    {
        $src = php_strip_whitespace(self::WEB . 'pages/admin.edit.ban.php');
        $gate = strpos($src, "preg_match('/^[a-f0-9]{32}\$/D', \$did)");
        $store = strpos($src, 'REPLACE INTO `:prefix_demos`');
        $this->assertNotFalse($gate, 'did must be checked against the uploader hash shape');
        $this->assertNotFalse($store);
        $this->assertLessThan($store, $gate);
    }

    public function testEditModValidatesIconName(): void
    {
        $src = php_strip_whitespace(self::WEB . 'pages/admin.edit.mod.php');
        $this->assertStringContainsString('UploadHandler::isSafeStoredName($rawIcon)', $src);
    }
}
