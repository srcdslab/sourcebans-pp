<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Security;

/**
 * Strings the game plugin copies into its backup config files
 * (`sb_admins.cfg`, `sb_admin_groups.cfg`): admin names, server group
 * names and server passwords.
 *
 * The plugin writes those files with Valve KeyValues and sbpp_admcfg
 * reads them back (SMC) when the database is down. KeyValues escapes
 * `"` but not `\`, and writes control characters raw, so `\"` or a
 * newline in a value ends the quoted string early and the rest of the
 * value is read as config (#89, #91). Refuse those characters on every
 * panel write path. The plugin also replaces them before writing, for
 * rows the panel didn't write.
 */
final class PluginConfigString
{
    /** User-facing reason, appended to "The admin name" / "The group name". */
    public const RULE = 'cannot contain quotes, backslashes or control characters.';

    public static function isSafe(string $value): bool
    {
        return preg_match('/["\\\\\x00-\x1F\x7F]/', $value) === 0;
    }
}
