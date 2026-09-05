<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Rest;

use Sbpp\Api\ApiError;
use Sbpp\Auth\UserManager;
use Sbpp\Config;

/**
 * Hide-* flags for REST GET of bans/comms. Same gate as `api_bans_detail`:
 * `is_admin()` sees IPs and admin names; anonymous callers follow the
 * public panel toggles.
 */
final class PublicVisibility
{
    public static function hidePlayerIps(): bool
    {
        return Config::getBool('banlist.hideplayerips') && !self::isAdmin();
    }

    public static function hideAdminName(): bool
    {
        return Config::getBool('banlist.hideadminname') && !self::isAdmin();
    }

    public static function isAdmin(): bool
    {
        $userbank = $GLOBALS['userbank'] ?? null;
        return $userbank instanceof UserManager && $userbank->is_admin();
    }

    /**
     * Anonymous GET `/comms` (and nested `/comms/{cid}/comments`) is 404
     * when Comm blocks are off. A PAT still reads.
     */
    public static function assertCommsFeature(): void
    {
        if (!Config::getBool('config.enablecomms') && !self::isAdmin()) {
            throw new ApiError('not_found', 'Not found.', null, 404);
        }
    }
}
