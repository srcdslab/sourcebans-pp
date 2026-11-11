<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Security;

/**
 * Single source of truth for "who may grant, hold, or touch the Owner flag".
 *
 * Only an Owner may:
 *  - put the `ADMIN_OWNER` bit on a web group (groups.add / groups.edit),
 *  - assign a web group that carries `ADMIN_OWNER` to an admin,
 *  - modify an admin who is an Owner (directly or through their web group).
 *
 * The checks read the database directly instead of `UserManager::HasAccess()`
 * because `HasAccess()` returns false for a deactivated admin: a disabled
 * Owner must stay protected from non-owners too.
 */
final class OwnerGuard
{
    /** True when the caller holds the Owner flag (own or group flags). */
    public static function callerIsOwner(): bool
    {
        $userbank = $GLOBALS['userbank'] ?? null;
        return $userbank !== null && $userbank->HasAccess(\WebPermission::Owner);
    }

    /** True when `$flags` carries the Owner bit. */
    public static function maskHasOwner(int $flags): bool
    {
        return ($flags & ADMIN_OWNER) !== 0;
    }

    /** True when web group `$gid` exists and carries the Owner bit. */
    public static function isOwnerGroup(int $gid): bool
    {
        if ($gid <= 0) {
            return false;
        }
        $row = $GLOBALS['PDO']->query('SELECT flags FROM `:prefix_groups` WHERE gid = ?')->single([$gid]);
        return is_array($row) && self::maskHasOwner((int) $row['flags']);
    }

    /**
     * True when admin `$aid` is an Owner through their own flags or their
     * web group, whether or not the account is enabled.
     */
    public static function isOwnerAdmin(int $aid): bool
    {
        if ($aid <= 0) {
            return false;
        }
        $row = $GLOBALS['PDO']->query(
            'SELECT A.extraflags, G.flags AS gflags
               FROM `:prefix_admins` A
               LEFT JOIN `:prefix_groups` G ON G.gid = A.gid
              WHERE A.aid = ?'
        )->single([$aid]);
        if (!is_array($row)) {
            return false;
        }
        return self::maskHasOwner((int) $row['extraflags'] | (int) ($row['gflags'] ?? 0));
    }

    /**
     * True when the caller may modify admin `$aid`: Owners may modify
     * anyone, everyone else may only modify non-owners.
     */
    public static function canModifyAdmin(int $aid): bool
    {
        return self::callerIsOwner() || !self::isOwnerAdmin($aid);
    }
}
