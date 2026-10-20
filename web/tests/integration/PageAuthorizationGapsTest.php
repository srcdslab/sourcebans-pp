<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * #55: the admin router only checks a broad per-section mask, so edit
 * pages and the demo endpoint must apply their own finer gate.
 *
 * Static-shape assertions, like AdminExportPermissionTest: the deny paths
 * end in PageDie() / exit, which PHPUnit can't catch in-process. Sources
 * are comment-stripped so explanatory comments neither satisfy nor trip a
 * check, and each gate must come before the data read it protects.
 */
final class PageAuthorizationGapsTest extends TestCase
{
    private const WEB = __DIR__ . '/../../';

    private static function code(string $relative): string
    {
        $path = self::WEB . $relative;
        self::assertFileExists($path);
        return php_strip_whitespace($path);
    }

    private static function assertBefore(string $haystack, string $first, string $second, string $why): void
    {
        $a = strpos($haystack, $first);
        $b = strpos($haystack, $second);
        self::assertNotFalse($a, "missing: $first");
        self::assertNotFalse($b, "missing: $second");
        self::assertLessThan($b, $a, $why);
    }

    public function testCommEditUsesPositiveOwnershipGate(): void
    {
        $src = self::code('pages/admin.edit.comms.php');

        // The inverted chain let EditOwnBans / EditGroupBans holders edit any block.
        $this->assertStringNotContainsString('(!$userbank->HasAccess(WebPermission::EditOwnBans) &&', $src);
        $this->assertStringNotContainsString('(!$userbank->HasAccess(WebPermission::EditGroupBans) &&', $src);

        $this->assertStringContainsString(
            '($userbank->HasAccess(WebPermission::EditOwnBans) && (int) $res[\'aid\'] === $userbank->GetAid())',
            $src,
        );
        $this->assertStringContainsString(
            '($userbank->HasAccess(WebPermission::EditGroupBans) && (int) $res[\'gid\'] === (int) $userbank->GetProperty(\'gid\'))',
            $src,
        );
        $this->assertStringContainsString('if (!$canEditComm) {', $src);
    }

    public function testGroupBanEditorsCanReachCommEdits(): void
    {
        $this->assertMatchesRegularExpression(
            "/'comms' => \[\s*'permission' => [^\]]*ADMIN_EDIT_GROUP_BANS/",
            self::code('includes/page-builder.php'),
        );
        $this->assertMatchesRegularExpression(
            "/'endpoint' => 'comms',\s*'permission' => [^\]]*ADMIN_EDIT_GROUP_BANS/",
            self::code('pages/core/navbar.php'),
        );
    }

    public function testSubmissionDemosRequireSubmissionsFlagBeforeLookup(): void
    {
        $src = self::code('getdemo.php');

        $this->assertMatchesRegularExpression(
            '/\$type === DEMO_TYPE_SUBMISSION\s*&& !\$userbank->HasAccess\(WebPermission::mask\(WebPermission::Owner, WebPermission::BanSubmissions\)\)/',
            $src,
        );
        self::assertBefore(
            $src,
            'WebPermission::BanSubmissions',
            'FROM `:prefix_demos`',
            'The submission-demo gate must run before the demo lookup.',
        );
    }

    public function testContactPageGatesOnQueueFlagBeforeReadingEmail(): void
    {
        $src = self::code('pages/admin.email.php');

        // php_strip_whitespace() collapses the alignment spaces.
        $this->assertStringContainsString("'s' => [\\WebPermission::BanSubmissions,", $src);
        $this->assertStringContainsString("'p' => [\\WebPermission::BanProtests,", $src);
        self::assertBefore(
            $src,
            '$userbank->HasAccess(\WebPermission::mask(\WebPermission::Owner, $permission))',
            'SELECT email FROM',
            'The queue-flag gate must run before the reporter email is read.',
        );
        $this->assertStringNotContainsString('msg-red', $src);
    }

    public function testGroupEditorRequiresEditGroups(): void
    {
        $src = self::code('pages/admin.edit.group.php');

        self::assertBefore(
            $src,
            '$userbank->HasAccess(\WebPermission::mask(\WebPermission::Owner, \WebPermission::EditGroups))',
            '$pdo->query(',
            'The EditGroups gate must run before any group data is read.',
        );
    }
}
