<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Tests\Api;

use Sbpp\Security\PluginConfigString;

/**
 * #91: admin names and server group names are copied by the plugin into
 * sb_admins.cfg / sb_admin_groups.cfg (KeyValues). A backslash, a quote or
 * a control character can end a quoted string early there, so every panel
 * write path refuses them, like the server password (#89).
 */
final class PluginConfigStringTest extends RestTestCase
{
    private const NEW_STEAM64 = '76561198000000001';

    /** @return list<string> */
    private static function hostileNames(): array
    {
        return [
            'back\\slash',
            'has"quote',
            "new\nline",
            "tab\there",
            "nul\0byte",
            "del\x7F",
            '\\" } x { "auth" "steam" "identity" "STEAM_0:1:1" "flags" "z" }',
        ];
    }

    public function testHelperRefusesOnlyConfigBreakingCharacters(): void
    {
        foreach (self::hostileNames() as $hostile) {
            $this->assertFalse(PluginConfigString::isSafe($hostile), json_encode($hostile));
        }
        foreach (['Sidekick', 'Jean-Luc Picard', 'Ünïcødé ☺', 'a,b', '[Mod] #1', ''] as $fine) {
            $this->assertTrue(PluginConfigString::isSafe($fine), $fine);
        }
    }

    public function testServerPasswordCheckStillAppliesTheSameRule(): void
    {
        $this->assertFalse(\Sbpp\Security\PasswordGenerator::isSafeServerPassword('back\\slash'));
        $this->assertFalse(\Sbpp\Security\PasswordGenerator::isSafeServerPassword(str_repeat('a', 65)));
        $this->assertTrue(\Sbpp\Security\PasswordGenerator::isSafeServerPassword('pa$$w0rd!'));
    }

    public function testAdminsAddRefusesUnsafeAdminName(): void
    {
        $this->loginAsAdmin();
        foreach (self::hostileNames() as $i => $hostile) {
            $env = $this->api('admins.add', $this->adminParams([
                'name'  => $hostile,
                'steam' => 'STEAM_0:0:' . (8800 + $i),
            ]));
            $this->assertEnvelopeError($env, 'validation');
            $this->assertSame('name', $env['error']['field'], json_encode($hostile));
        }
        foreach ($this->rows('admins') as $admin) {
            $this->assertTrue(PluginConfigString::isSafe((string) $admin['user']), (string) $admin['user']);
        }
    }

    public function testAdminsAddRefusesUnsafeNewServerGroupName(): void
    {
        $this->loginAsAdmin();
        $env = $this->api('admins.add', $this->adminParams([
            'server_group' => 'n',
            'server_name'  => 'Mods\\',
        ]));
        $this->assertEnvelopeError($env, 'validation');
        $this->assertSame('servername_err', $env['error']['field']);
        $this->assertNull($this->row('srvgroups', ['name' => 'Mods\\']));
    }

    public function testGroupsAddRefusesUnsafeServerGroupName(): void
    {
        $this->loginAsAdmin();
        $env = $this->api('groups.add', [
            'name' => "Mods\"\n", 'type' => '2', 'bitmask' => 0, 'srvflags' => 'b',
        ]);
        $this->assertEnvelopeError($env, 'validation');
        $this->assertSame('name', $env['error']['field']);
    }

    public function testGroupsAddKeepsAcceptingWebGroupNames(): void
    {
        // Web groups never reach the plugin files: no new restriction.
        $this->loginAsAdmin();
        $env = $this->api('groups.add', [
            'name' => 'Web "staff"', 'type' => '1', 'bitmask' => 0, 'srvflags' => '',
        ]);
        $this->assertTrue($env['ok'], json_encode($env));
    }

    public function testGroupsEditRefusesUnsafeServerGroupName(): void
    {
        $this->loginAsAdmin();
        $this->api('groups.add', ['name' => 'Mods', 'type' => '2', 'bitmask' => 0, 'srvflags' => 'b']);
        $row = $this->row('srvgroups', ['name' => 'Mods']);
        $this->assertNotNull($row);

        $env = $this->api('groups.edit', [
            'gid' => (int) $row['id'], 'web_flags' => 0, 'srv_flags' => 'b',
            'type' => 'srv', 'name' => 'Mods\\',
        ]);
        $this->assertEnvelopeError($env, 'validation');
        $this->assertSame('name', $env['error']['field']);
        $this->assertNotNull($this->row('srvgroups', ['name' => 'Mods']));
    }

    public function testRestCreateRefusesUnsafeAdminName(): void
    {
        $token = $this->mintToken();
        $response = $this->rest('PUT', '/admins/' . self::NEW_STEAM64, ['name' => 'Rest\\Bot'], $token);
        $this->assertRestError($response, 400, 'validation');
    }

    public function testRestUpdateRefusesUnsafeAdminName(): void
    {
        $token = $this->mintToken();
        $created = $this->rest('PUT', '/admins/' . self::NEW_STEAM64, ['name' => 'RestBot'], $token);
        $this->assertSame(201, $created->status, json_encode($created->payload));

        // Not a trailing newline: the service trims the name first.
        $response = $this->rest('PUT', '/admins/' . self::NEW_STEAM64, ['name' => "Rest\nBot"], $token);
        $this->assertRestError($response, 400, 'validation');
    }

    public function testPageHandlersApplyTheRule(): void
    {
        // Page handlers (admin details form, install wizard) aren't
        // drivable from PHPUnit; pin the check in their source instead.
        $web = __DIR__ . '/../../';
        foreach (['pages/admin.edit.admindetails.php', 'install/pages/page.5.php'] as $file) {
            $src = php_strip_whitespace($web . $file);
            $this->assertStringContainsString('PluginConfigString::isSafe(', $src, $file);
        }
    }

    /** Same shape as AdminsTest::adminParams(). */
    private function adminParams(array $overrides = []): array
    {
        return array_merge([
            'mask'             => 0,
            'srv_mask'         => '',
            'name'             => 'Sidekick',
            'steam'            => 'STEAM_0:0:7777',
            'email'            => 'side@kick.test',
            'password'         => 'longpassword',
            'password2'        => 'longpassword',
            'server_group'     => 'c',
            'web_group'        => 'c',
            'server_password'  => '-1',
            'web_name'         => '',
            'server_name'      => '0',
            'servers'          => '',
            'single_servers'   => '',
        ], $overrides);
    }
}
