<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * sbpp/sourcebans-pp#1554 — the player drawer's Overview pane must
 * surface a getdemo.php download link when the ban has an uploaded
 * demo (`bans.detail` carries `demo_count`). SourceBans 1.x rendered a
 * "Review Demo" affordance on the sliding ban panel; the 2.0 drawer
 * dropped it.
 */
final class BanDrawerDemoDownloadTest extends TestCase
{
    private static function panelRoot(): string
    {
        return dirname(__DIR__, 2);
    }

    public function testDrawerOverviewBuildsDemoDownloadLink(): void
    {
        $src = (string) file_get_contents(self::panelRoot() . '/themes/default/js/theme.js');
        $this->assertStringContainsString('data.demo_count', $src);
        $this->assertStringContainsString('getdemo.php?type=B&id=', $src);
        $this->assertStringContainsString('data-testid="drawer-demo-download"', $src);
    }

    public function testBansDetailApiExposesDemoCount(): void
    {
        $src = (string) file_get_contents(self::panelRoot() . '/api/handlers/bans.php');
        $this->assertStringContainsString("'demo_count'", $src);
    }
}
