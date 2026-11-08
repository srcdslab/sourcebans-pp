<?php

namespace Sbpp\Tests\Api;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * Security audit 2026-11: a delegated (non-owner) admin must never be able
 * to become Owner, nor strip / remove an existing Owner.
 *
 * Every test logs in as a non-owner who holds exactly the flag the attack
 * needs, then asserts the request is refused AND the database is unchanged.
 */
final class OwnerEscalationTest extends ApiTestCase
{
    private function createAdmin(string $user, int $flags, int $gid = -1): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_admins` (user, authid, password, gid, email, validate, extraflags, immunity)
             VALUES (?, ?, ?, ?, ?, NULL, ?, 0)',
            DB_PREFIX,
        ))->execute([
            $user,
            'STEAM_0:0:' . random_int(1000, 9_999_999),
            password_hash('x', PASSWORD_BCRYPT),
            $gid,
            $user . '@example.test',
            $flags,
        ]);
        return (int) $pdo->lastInsertId();
    }

    private function createWebGroup(string $name, int $flags): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_groups` (type, name, flags) VALUES (1, ?, ?)',
            DB_PREFIX,
        ))->execute([$name, $flags]);
        return (int) $pdo->lastInsertId();
    }

    private function groupFlags(int $gid): int
    {
        return (int) $this->row('groups', ['gid' => $gid])['flags'];
    }

    private function adminRow(int $aid): array
    {
        $row = $this->row('admins', ['aid' => $aid]);
        $this->assertNotNull($row);
        return $row;
    }

    public function testGroupsEditRefusesOwnerBitForNonOwner(): void
    {
        $gid = $this->createWebGroup('Helpers', ADMIN_LIST_ADMINS);
        $attacker = $this->createAdmin('group-editor', ADMIN_EDIT_GROUPS, $gid);
        $this->loginAs($attacker);

        $env = $this->api('groups.edit', [
            'gid' => $gid, 'type' => 'web', 'name' => 'Helpers', 'web_flags' => ADMIN_OWNER,
        ]);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertSame(ADMIN_LIST_ADMINS, $this->groupFlags($gid));
    }

    public function testGroupsEditRefusesOwnerBitThroughServerType(): void
    {
        $gid = $this->createWebGroup('Helpers2', ADMIN_LIST_ADMINS);
        $this->loginAs($this->createAdmin('group-editor2', ADMIN_EDIT_GROUPS, $gid));

        $env = $this->api('groups.edit', [
            'gid' => $gid, 'type' => 'server', 'name' => 'Helpers2', 'web_flags' => ADMIN_OWNER,
        ]);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertSame(ADMIN_LIST_ADMINS, $this->groupFlags($gid));
    }

    public function testGroupsEditRefusesToTouchAnOwnerGroupForNonOwner(): void
    {
        $ownerGroup = $this->createWebGroup('Owners', ADMIN_OWNER);
        $this->loginAs($this->createAdmin('group-editor3', ADMIN_EDIT_GROUPS));

        $env = $this->api('groups.edit', [
            'gid' => $ownerGroup, 'type' => 'web', 'name' => 'Owners', 'web_flags' => 0,
        ]);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertSame(ADMIN_OWNER, $this->groupFlags($ownerGroup));
    }

    public function testGroupsEditStillAllowsOwnerToGrantOwner(): void
    {
        $gid = $this->createWebGroup('Promote', ADMIN_LIST_ADMINS);
        $this->loginAsAdmin();

        $env = $this->api('groups.edit', [
            'gid' => $gid, 'type' => 'web', 'name' => 'Promote', 'web_flags' => ADMIN_OWNER,
        ]);

        $this->assertTrue($env['ok'], json_encode($env));
        $this->assertSame(ADMIN_OWNER, $this->groupFlags($gid));
    }

    public function testGroupsAddRefusesOwnerBitForNonOwner(): void
    {
        $this->loginAs($this->createAdmin('group-adder', ADMIN_ADD_GROUP));

        $env = $this->api('groups.add', [
            'name' => 'Sneaky', 'type' => '1', 'bitmask' => ADMIN_OWNER, 'srvflags' => '',
        ]);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertNull($this->row('groups', ['name' => 'Sneaky']));
    }

    public function testGroupsRemoveRefusesOwnerGroupForNonOwner(): void
    {
        $ownerGroup = $this->createWebGroup('Owners2', ADMIN_OWNER);
        $this->loginAs($this->createAdmin('group-deleter', ADMIN_DELETE_GROUPS));

        $env = $this->api('groups.remove', ['gid' => $ownerGroup, 'type' => 'web']);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertNotNull($this->row('groups', ['gid' => $ownerGroup]));
    }

    public function testGroupsRemoveRefusesOwnerGroupThroughServerType(): void
    {
        // `type` is client-controlled; the server branch also deletes from
        // :prefix_groups, so it must not be a way around the guard.
        $ownerGroup = $this->createWebGroup('Owners2b', ADMIN_OWNER);
        $this->loginAs($this->createAdmin('group-deleter2', ADMIN_DELETE_GROUPS));

        $env = $this->api('groups.remove', ['gid' => $ownerGroup, 'type' => 'server']);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertNotNull($this->row('groups', ['gid' => $ownerGroup]));
    }

    public function testGroupsRemoveServerTypeNeverDeletesAWebGroup(): void
    {
        $webGroup = $this->createWebGroup('PlainWeb', ADMIN_LIST_ADMINS);
        $this->loginAsAdmin();

        $this->api('groups.remove', ['gid' => $webGroup, 'type' => 'server']);

        $this->assertNotNull($this->row('groups', ['gid' => $webGroup]));
    }

    public function testAdminsAddRefusesExistingOwnerGroupForNonOwner(): void
    {
        $ownerGroup = $this->createWebGroup('Owners3', ADMIN_OWNER);
        $this->loginAs($this->createAdmin('admin-adder', ADMIN_ADD_ADMINS));

        $env = $this->api('admins.add', [
            'mask' => 0, 'srv_mask' => '', 'name' => 'puppet', 'steam' => 'STEAM_0:0:424242',
            'email' => 'puppet@example.test', 'password' => 'Password123!', 'password2' => 'Password123!',
            'server_group' => 'c', 'web_group' => (string) $ownerGroup, 'server_password' => '-1',
            'web_name' => '', 'server_name' => '0', 'servers' => '', 'single_servers' => '',
        ]);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertNull($this->row('admins', ['user' => 'puppet']));
    }

    public function testBulkSetWebGroupRefusesOwnerGroupForNonOwner(): void
    {
        $ownerGroup = $this->createWebGroup('Owners4', ADMIN_OWNER);
        $attacker = $this->createAdmin('admin-editor', ADMIN_EDIT_ADMINS);
        $this->loginAs($attacker);

        $env = $this->api('admins.bulk', ['op' => 'set_web_group', 'aids' => [$attacker], 'gid' => $ownerGroup]);

        $this->assertTrue($env['ok'], json_encode($env));
        $this->assertSame([], $env['data']['applied']);
        $this->assertSame('forbidden', $env['data']['skipped'][0]['reason']);
        $this->assertNotSame($ownerGroup, (int) $this->adminRow($attacker)['gid']);
    }

    public function testBulkSkipsOwnerTargetsForNonOwner(): void
    {
        $this->loginAs($this->createAdmin('admin-editor2', ADMIN_EDIT_ADMINS));

        $env = $this->api('admins.bulk', ['op' => 'set_srv_group', 'aids' => [Fixture::adminAid()], 'srv_group_id' => 0]);

        $this->assertTrue($env['ok'], json_encode($env));
        $this->assertSame([], $env['data']['applied']);
        $this->assertSame('owner', $env['data']['skipped'][0]['reason']);
    }

    public function testEditPermsRefusesOwnerTargetForNonOwner(): void
    {
        $this->loginAs($this->createAdmin('admin-editor3', ADMIN_EDIT_ADMINS));

        $env = $this->api('admins.edit_perms', ['aid' => Fixture::adminAid(), 'web_flags' => 0, 'srv_flags' => '']);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertSame(ADMIN_OWNER, (int) $this->adminRow(Fixture::adminAid())['extraflags'] & ADMIN_OWNER);
    }

    public function testEditPermsRefusesOwnerViaGroupTargetForNonOwner(): void
    {
        $ownerGroup = $this->createWebGroup('Owners5', ADMIN_OWNER);
        $groupOwner = $this->createAdmin('group-owner', 0, $ownerGroup);
        $this->loginAs($this->createAdmin('admin-editor4', ADMIN_EDIT_ADMINS));

        $env = $this->api('admins.edit_perms', ['aid' => $groupOwner, 'web_flags' => 0, 'srv_flags' => 'z']);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertSame('', (string) $this->adminRow($groupOwner)['srv_flags']);
    }

    public function testRemoveAndDeactivateProtectOwnerViaGroup(): void
    {
        $ownerGroup = $this->createWebGroup('Owners6', ADMIN_OWNER);
        $groupOwner = $this->createAdmin('group-owner2', 0, $ownerGroup);
        $this->loginAsAdmin();

        $this->assertEnvelopeError($this->api('admins.deactivate', ['aid' => $groupOwner]), 'cannot_deactivate_owner');
        $this->assertEnvelopeError($this->api('admins.remove', ['aid' => $groupOwner]), 'cannot_delete_owner');
        $this->assertNotNull($this->row('admins', ['aid' => $groupOwner]));
    }
    public function testReactivateRefusesADeactivatedOwnerForNonOwner(): void
    {
        // HasAccess() reads a disabled account as flag-less, so a
        // deactivated Owner must be protected by OwnerGuard, not by it.
        $ownerGroup = $this->createWebGroup('Owners7', ADMIN_OWNER);
        $retired = $this->createAdmin('retired-owner', 0, $ownerGroup);
        Fixture::rawPdo()->prepare(sprintf('UPDATE `%s_admins` SET enabled = 0 WHERE aid = ?', DB_PREFIX))
            ->execute([$retired]);
        $this->loginAs($this->createAdmin('admin-deleter', ADMIN_DELETE_ADMINS));

        $env = $this->api('admins.reactivate', ['aid' => $retired]);

        $this->assertEnvelopeError($env, 'forbidden');
        $this->assertSame(0, (int) $this->adminRow($retired)['enabled']);
    }

    public function testOwnerCanStillReactivateAnOwner(): void
    {
        $retired = $this->createAdmin('retired-owner2', ADMIN_OWNER);
        Fixture::rawPdo()->prepare(sprintf('UPDATE `%s_admins` SET enabled = 0 WHERE aid = ?', DB_PREFIX))
            ->execute([$retired]);
        $this->loginAsAdmin();

        $env = $this->api('admins.reactivate', ['aid' => $retired]);

        $this->assertTrue($env['ok'], json_encode($env));
        $this->assertSame(1, (int) $this->adminRow($retired)['enabled']);
    }
}
