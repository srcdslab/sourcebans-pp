<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * #60: the moderation-queue demo cell uses Lucide (the default theme
 * ships no Font Awesome) and exportbans.php serves its .cfg files as
 * text/plain. Static, comment-stripped checks.
 */
final class DemoIconExportHeadersTest extends TestCase
{
    private static function code(string $relative): string
    {
        $path = __DIR__ . '/../../' . $relative;
        self::assertFileExists($path);
        return php_strip_whitespace($path);
    }

    public function testSubmissionDemoCellUsesLucideIcons(): void
    {
        $src = self::code('pages/admin.bans.php');

        $this->assertStringNotContainsString('fa-video', $src);
        // Current queue + archive both render the cell.
        $this->assertSame(2, substr_count($src, '<i data-lucide="download"'));
        $this->assertSame(2, substr_count($src, '<i data-lucide="video-off"'));
        // "No demo" is text, not a dead `href="#"` link.
        $this->assertStringNotContainsString('href=\"#\"', $src);
    }

    public function testExportBansServesPlainTextAndRejectsUnknownTypes(): void
    {
        $src = self::code('exportbans.php');

        $this->assertStringNotContainsString('x-httpd-php', $src);
        $this->assertStringContainsString("header('Content-Type: text/plain; charset=utf-8');", $src);
        $this->assertStringContainsString("header('X-Content-Type-Options: nosniff');", $src);
        $this->assertStringContainsString('default => exportbans_die(400,', $src);
        $this->assertStringContainsString('exportbans_die(403,', $src);
    }
}
