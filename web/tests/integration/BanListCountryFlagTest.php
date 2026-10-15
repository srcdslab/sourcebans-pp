<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Util\CountryFlag;
use Sbpp\View\BanListView;
use Sbpp\View\Renderer;
use Smarty\Smarty;

/**
 * Country-of-origin flags on the public ban list.
 *
 * v1.x drew a flag next to every banned player. The v2.0 rewrite of
 * page_bans.tpl kept the GeoIP lookup + `banlist.nocountryfetch`
 * setting but never rendered the flag. These tests pin:
 *
 *  - {@see CountryFlag} normalisation (the stored column is written by
 *    the plugin too, so it is untrusted) and the GeoIP fallback;
 *  - the desktop + mobile flag render driven by `country_code`;
 *  - the settings toggle being the positive "Show player country flags"
 *    form of the inverted key.
 */
final class BanListCountryFlagTest extends ApiTestCase
{
    protected function tearDown(): void
    {
        unset($GLOBALS['theme']);
        parent::tearDown();
    }

    public function testNormalizeAcceptsOnlyBundledTwoLetterCodes(): void
    {
        $this->assertSame('fr', CountryFlag::normalize('FR'));
        $this->assertSame('de', CountryFlag::normalize(' de '));
        $this->assertNull(CountryFlag::normalize(null));
        $this->assertNull(CountryFlag::normalize(''));
        $this->assertNull(CountryFlag::normalize('zz'), 'zz is the lookup-failed placeholder');
        $this->assertNull(CountryFlag::normalize('qq'), 'no bundled flag for qq');
        $this->assertNull(CountryFlag::normalize('<b>'));
        $this->assertNull(CountryFlag::normalize('../x'));
        $this->assertNull(CountryFlag::normalize("f\nr"));
    }

    public function testResolvePrefersStoredValueThenFallsBackToGeoIp(): void
    {
        $this->assertSame('fr', CountryFlag::resolve('FR', '8.8.8.8', $looked));
        $this->assertNull($looked, 'no lookup when the column is already filled');

        $this->assertSame('us', CountryFlag::resolve(null, '8.8.8.8', $looked));
        $this->assertSame('US', $looked, 'raw lookup result is handed back for caching');

        $this->assertNull(CountryFlag::resolve('', '10.0.0.1', $looked));
        $this->assertSame('zz', $looked, 'private IPs cache the zz placeholder');

        $this->assertNull(CountryFlag::resolve('', '', $looked));
        $this->assertNull($looked, 'no IP, no lookup');
    }

    public function testEnabledFollowsInvertedSetting(): void
    {
        $this->assertFalse(CountryFlag::enabled(), 'data.sql ships banlist.nocountryfetch=1 (off)');

        \Sbpp\Tests\Fixture::rawPdo()->prepare(sprintf(
            "REPLACE INTO `%s_settings` (`setting`, `value`) VALUES ('banlist.nocountryfetch', '0')",
            DB_PREFIX
        ))->execute();
        \Config::init($GLOBALS['PDO']);

        $this->assertTrue(CountryFlag::enabled());
    }

    public function testFlagRendersOnDesktopRowAndMobileCard(): void
    {
        $html = $this->renderBanList(['country_code' => 'fr', 'country_name' => 'France']);

        $this->assertMatchesRegularExpression(
            '#<img class="country-flag" src="images/country/fr\.png"[^>]*alt="FR" title="France" data-testid="ban-country-flag">#',
            $html,
        );
        $this->assertStringContainsString('data-testid="ban-country-flag-mobile"', $html);
    }

    public function testNoFlagWhenCountryUnknownOrDisabled(): void
    {
        $html = $this->renderBanList(['country_code' => '', 'country_name' => '']);

        $this->assertStringNotContainsString('data-testid="ban-country-flag"', $html);
        $this->assertStringNotContainsString('data-testid="ban-country-flag-mobile"', $html);
    }

    public function testSettingsFormUsesPositiveToggle(): void
    {
        $tpl = (string) file_get_contents(SB_THEMES . 'default/page_admin_settings_settings.tpl');
        $this->assertStringContainsString('name="banlist_showcountryflags"{if !$banlist_nocountryfetch} checked{/if}', $tpl);

        $handler = (string) file_get_contents(ROOT . 'pages/admin.settings.php');
        $this->assertStringContainsString(
            "\$nocountryfetch = (isset(\$_POST['banlist_showcountryflags']) && \$_POST['banlist_showcountryflags'] === 'on') ? 0 : 1;",
            $handler,
            'checked "Show player country flags" must store banlist.nocountryfetch=0',
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function renderBanList(array $overrides): string
    {
        $this->loginAsAdmin();
        $this->bootstrapSmartyTheme();

        $row = array_merge([
            'bid'             => 7,
            'name'            => 'FlagPlayer',
            'steam'           => 'STEAM_0:1:777',
            'state'           => 'permanent',
            'length'          => 0,
            'length_human'    => 'Permanent',
            'banned'          => 1700000000,
            'banned_human'    => '2023-11-14 22:13',
            'banned_iso'      => '2023-11-14T22:13:20+00:00',
            'sname'           => 'Web Ban',
            'reason'          => 'aimbot',
            'aname'           => 'admin',
            'ban_ip_raw'      => '',
            'can_edit_ban'    => false,
            'can_unban'       => false,
            'can_delete_ban'  => false,
            'mod_icon'        => 'web.png',
            'country'         => '',
            'demo_available'  => false,
            'view_delete'     => false,
            'type'            => 0,
            'commentdata'     => 'None',
            'avatar_initials' => 'FL',
            'avatar_hue'      => 60,
        ], $overrides);

        $view = new BanListView(
            ban_list:        [$row],
            ban_nav:         '',
            total_bans:      1,
            view_bans:       false,
            view_comments:   false,
            searchlink:      '',
            hidetext:        'Hide',
            hideadminname:   false,
            hideplayerips:   false,
            groupban:        false,
            friendsban:      false,
            general_unban:   false,
            can_delete:      false,
            can_export:      false,
            admin_postkey:   'test-postkey',
            can_add_ban:     false,
            is_filtered:     false,
            server_list:     [],
            filters:         ['search' => '', 'server' => '', 'time' => '', 'state' => ''],
            is_advanced_search_open: false,
            active_state:    '',
            chip_base_link:  '',
        );

        ob_start();
        try {
            Renderer::render($GLOBALS['theme'], $view);
        } finally {
            $html = (string) ob_get_clean();
        }
        return $html;
    }

    /** Same Smarty wiring as BanListIpColumnTest (init.php equivalent). */
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
}
