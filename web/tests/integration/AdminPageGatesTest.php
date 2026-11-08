<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Security audit 2026-11: page-level gates the admin router does not
 * provide on its own. The deny paths `return` / `exit` inside a page
 * include, so these are static-shape checks on comment-stripped source
 * (same approach as PageAuthorizationGapsTest): each gate must exist and
 * run before the write it protects.
 */
final class AdminPageGatesTest extends TestCase
{
    private const WEB = __DIR__ . '/../../';

    private static function assertBefore(string $src, string $first, string $second): void
    {
        $a = strpos($src, $first);
        $b = strpos($src, $second);
        self::assertNotFalse($a, "missing: $first");
        self::assertNotFalse($b, "missing: $second");
        self::assertLessThan($b, $a, "`$first` must run before `$second`");
    }

    public function testOverridesSectionRequiresAddAdmins(): void
    {
        $src = php_strip_whitespace(self::WEB . 'pages/admin.admins.php');
        $section = (int) strpos($src, "if (\$section === 'overrides') {");
        $tail = substr($src, $section);
        self::assertBefore($tail, 'if (!$canAddAdmins) {', '/admin.overrides.php');
    }

    public function testBanImportRequiresBanImport(): void
    {
        $src = php_strip_whitespace(self::WEB . 'pages/admin.bans.php');
        self::assertBefore($src, '$_POST[\'action\'] == "importBans" && !$canImport', '$bannedcfg = file(');
    }

    public function testLogClearRequiresCsrfToken(): void
    {
        $src = php_strip_whitespace(self::WEB . 'pages/admin.settings.php');
        self::assertBefore($src, '\CSRF::rejectIfInvalid();', 'TRUNCATE TABLE `:prefix_log`');

        $tpl = (string) file_get_contents(self::WEB . 'themes/default/page_admin_settings_logs.tpl');
        $this->assertStringContainsString('log_clear=true&csrf_token=', $tpl);
    }
}
