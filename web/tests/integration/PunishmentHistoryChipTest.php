<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;
use Smarty\Smarty;

/**
 * Punishment history chip on the public banlist + commslist.
 *
 * v1.x showed how many times a player had been punished ("N (search)"
 * on the ban list, mute / gag counts on the comms list). The page
 * handlers kept computing `history_count` / `mute_count` / `gag_count`
 * after the v2.0 theme rewrite, but the new templates never rendered
 * them, so admins had to scroll a filtered list to count a repeat
 * offender's punishments. The chip brings the number back next to the
 * player name, only for players with more than one punishment, linked
 * to a search for every punishment on the same identity.
 *
 * Mirrors `BanlistCommentsVisibilityTest`'s in-process Smarty +
 * page-handler render harness.
 */
final class PunishmentHistoryChipTest extends ApiTestCase
{
    private const REPEAT_STEAM = 'STEAM_0:1:73001';
    private const SINGLE_STEAM = 'STEAM_0:1:73002';
    private const REPEAT_IP    = '203.0.113.77';
    private const COMM_STEAM   = 'STEAM_0:1:73010';
    private const COMM_SINGLE  = 'STEAM_0:1:73011';

    protected function setUp(): void
    {
        parent::setUp();
        $this->seedRows();
        $this->bootstrapSmartyTheme();
    }

    protected function tearDown(): void
    {
        $_GET     = [];
        $_SESSION = [];
        unset($GLOBALS['theme']);
        parent::tearDown();
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistShowsLinkedChipForRepeatOffenderOnly(): void
    {
        $this->loginAsAdmin();
        $_GET = ['p' => 'banlist'];

        $html = $this->renderPage('page.banlist.php');

        $steamUrl = 'index.php?p=banlist&amp;searchText=' . urlencode(self::REPEAT_STEAM);
        $this->assertMatchesRegularExpression(
            '#<a class="history-chip" href="' . preg_quote($steamUrl, '#') . '"\s+data-testid="ban-history-chip"\s+title="3 bans on record"#',
            $html,
            'a player with 3 Steam bans must get a linked chip reading 3, pointing at the Steam ID search',
        );
        $this->assertSame(
            6,
            substr_count($html, 'title="3 bans on record"'),
            'each of the 3 rows carries the chip twice (desktop table + mobile card)',
        );
        $this->assertStringContainsString('data-testid="ban-history-chip-mobile"', $html);
        $this->assertSame(
            0,
            preg_match('#searchText=' . preg_quote(urlencode(self::SINGLE_STEAM), '#') . '#', $html),
            'a player with a single ban must not get a chip',
        );
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistIpChipLinksForAdmin(): void
    {
        $this->setSetting('banlist.hideplayerips', '1');
        $this->loginAsAdmin();
        $_GET = ['p' => 'banlist'];

        $html = $this->renderPage('page.banlist.php');

        $this->assertStringContainsString(
            'href="index.php?p=banlist&amp;searchText=' . self::REPEAT_IP . '"',
            $html,
            'admins see IPs, so the IP-ban chip links to the IP search',
        );
        $this->assertStringContainsString('title="2 bans on record"', $html);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistIpChipHasNoLinkWhenIpsAreHidden(): void
    {
        $this->setSetting('banlist.hideplayerips', '1');
        $_GET = ['p' => 'banlist'];

        $html = $this->renderPage('page.banlist.php');

        $this->assertStringContainsString(
            'title="2 bans on record"',
            $html,
            'the count itself is still shown to the public',
        );
        $this->assertStringNotContainsString(
            self::REPEAT_IP,
            $html,
            'the chip must not leak a hidden IP through its search URL',
        );
        $this->assertMatchesRegularExpression(
            '#<span class="history-chip"\s+data-testid="ban-history-chip"\s+title="2 bans on record"#',
            $html,
            'without a link the chip renders as a static span',
        );
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCommslistChipSplitsMutesGagsAndSilences(): void
    {
        $this->loginAsAdmin();
        $_GET = ['p' => 'commslist'];

        $html = $this->renderPage('page.commslist.php');

        $url = 'index.php?p=commslist&amp;searchText=' . urlencode(self::COMM_STEAM);
        $this->assertMatchesRegularExpression(
            '#<a class="history-chip" href="' . preg_quote($url, '#') . '"\s+data-testid="comm-history-chip"\s+title="2 mutes, 1 gag, 1 silence on record"#',
            $html,
            '2 mutes + 1 gag + 1 silence on the same Steam ID must render a linked chip with the split in the tooltip',
        );
        $this->assertMatchesRegularExpression(
            '#data-testid="comm-history-mutes"><i data-lucide="mic-off"[^>]*></i><span class="tabular-nums">2</span>#',
            $html,
        );
        $this->assertMatchesRegularExpression(
            '#data-testid="comm-history-gags"><i data-lucide="message-square-off"[^>]*></i><span class="tabular-nums">1</span>#',
            $html,
        );
        $this->assertMatchesRegularExpression(
            '#data-testid="comm-history-silences"><i data-lucide="volume-x"[^>]*></i><span class="tabular-nums">1</span>#',
            $html,
            'type 3 silence rows count too (forks / imports store them as one row)',
        );
        $this->assertStringContainsString('data-testid="comm-history-chip-mobile"', $html);
        $this->assertSame(
            0,
            preg_match('#searchText=' . preg_quote(urlencode(self::COMM_SINGLE), '#') . '"\s+data-testid="comm-history-chip"#', $html),
            'a player with a single block must not get a chip',
        );
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function setSetting(string $key, string $value): void
    {
        Fixture::rawPdo()->prepare(sprintf(
            'REPLACE INTO `%s_settings` (`setting`, `value`) VALUES (?, ?)',
            DB_PREFIX,
        ))->execute([$key, $value]);
        \Config::init($GLOBALS['PDO']);
    }

    private function seedRows(): void
    {
        $pdo = Fixture::rawPdo();
        $now = time();
        $aid = Fixture::adminAid();

        $insertBan = $pdo->prepare(sprintf(
            'INSERT INTO `%s_bans` (type, ip, authid, name, created, ends, length, reason, aid, RemovedBy, RemovedOn, RemoveType)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            DB_PREFIX,
        ));
        // Repeat Steam offender: one active, two expired.
        $insertBan->execute([0, null, self::REPEAT_STEAM, 'RepeatPlayer', $now - 100, 0, 0, 'aimbot', $aid, null, null, null]);
        $insertBan->execute([0, null, self::REPEAT_STEAM, 'RepeatPlayer', $now - 9000, $now - 5000, 4000, 'wallhack', $aid, 0, $now - 5000, 'E']);
        $insertBan->execute([0, null, self::REPEAT_STEAM, 'RepeatPlayer', $now - 19000, $now - 15000, 4000, 'spinbot', $aid, 0, $now - 15000, 'E']);
        // Single ban: negative control.
        $insertBan->execute([0, null, self::SINGLE_STEAM, 'OneTimer', $now - 200, 0, 0, 'griefing', $aid, null, null, null]);
        // Repeat IP offender: two IP bans on the same address.
        $insertBan->execute([1, self::REPEAT_IP, '', 'IpPlayer', $now - 300, 0, 0, 'ban evasion', $aid, null, null, null]);
        $insertBan->execute([1, self::REPEAT_IP, '', 'IpPlayer', $now - 30000, $now - 20000, 10000, 'spam', $aid, 0, $now - 20000, 'E']);

        $insertComm = $pdo->prepare(sprintf(
            'INSERT INTO `%s_comms` (type, authid, name, created, ends, length, reason, aid, RemovedBy, RemovedOn, RemoveType)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            DB_PREFIX,
        ));
        // 2 mutes + 1 gag + 1 type 3 silence on the same Steam ID.
        $insertComm->execute([1, self::COMM_STEAM, 'Chatty', $now - 100, 0, 0, 'mic spam', $aid, null, null, null]);
        $insertComm->execute([1, self::COMM_STEAM, 'Chatty', $now - 9000, $now - 5000, 4000, 'mic spam', $aid, 0, $now - 5000, 'E']);
        $insertComm->execute([2, self::COMM_STEAM, 'Chatty', $now - 19000, $now - 15000, 4000, 'chat spam', $aid, 0, $now - 15000, 'E']);
        $insertComm->execute([3, self::COMM_STEAM, 'Chatty', $now - 29000, $now - 25000, 4000, 'spam', $aid, 0, $now - 25000, 'E']);
        // Single block: negative control.
        $insertComm->execute([2, self::COMM_SINGLE, 'Quiet', $now - 200, 0, 0, 'insults', $aid, null, null, null]);
    }

    private function bootstrapSmartyTheme(): void
    {
        require_once INCLUDES_PATH . '/SmartyCustomFunctions.php';
        require_once INCLUDES_PATH . '/View/View.php';
        require_once INCLUDES_PATH . '/View/Renderer.php';

        $compileDir = sys_get_temp_dir() . '/sbpp-test-smarty-' . getmypid();
        if (!is_dir($compileDir)) {
            mkdir($compileDir, 0o775, true);
        }

        $theme = new Smarty();
        $theme->setUseSubDirs(false);
        $theme->setCompileId('default');
        $theme->setCaching(Smarty::CACHING_OFF);
        $theme->setForceCompile(true);
        $theme->setTemplateDir(SB_THEMES . SB_THEME);
        $theme->setCompileDir($compileDir);
        $theme->setCacheDir($compileDir);
        $theme->setEscapeHtml(true);
        $theme->registerPlugin(Smarty::PLUGIN_FUNCTION, 'load_template', 'smarty_function_load_template');
        $theme->registerPlugin(Smarty::PLUGIN_FUNCTION, 'csrf_field',    'smarty_function_csrf_field');
        $theme->registerPlugin(Smarty::PLUGIN_BLOCK,    'has_access',    'smarty_block_has_access');
        $theme->registerPlugin('modifier', 'smarty_stripslashes',     'smarty_stripslashes');
        $theme->registerPlugin('modifier', 'smarty_htmlspecialchars', 'smarty_htmlspecialchars');

        $GLOBALS['theme']    = $theme;
        $GLOBALS['username'] = 'admin';
    }

    private function renderPage(string $page): string
    {
        ob_start();
        try {
            (function () use ($page): void {
                global $userbank, $theme;
                $userbank = $GLOBALS['userbank'];
                $theme    = $GLOBALS['theme'];
                require ROOT . 'pages/' . $page;
            })();
        } finally {
            $html = (string) ob_get_clean();
        }
        return $html;
    }
}
