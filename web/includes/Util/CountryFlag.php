<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Util;

use Sbpp\Config;

/**
 * Country-of-origin flag helpers for the public ban list and the
 * player drawer.
 *
 * v1.x rendered a flag next to every banned player (GeoIP lookup on
 * the ban IP, cached in `:prefix_bans.country`). The v2.0 rewrite kept
 * the lookup + the bundled flag set (`web/images/country/*.png`) but
 * stopped rendering the flag. This class is the single source for:
 *
 *  - the on/off gate (`banlist.nocountryfetch`, inverted: `1` = off,
 *    surfaced in Settings > Main as "Show player country flags");
 *  - normalising a stored / looked-up code into a safe flag slug.
 *
 * `:prefix_bans.country` is written by both the panel (MaxMind write-
 * back) and the SourceMod plugin, so the raw value is treated as
 * untrusted: anything that is not a two-letter code with a bundled
 * flag image collapses to `null` and no flag is drawn. `zz` is the
 * "lookup failed" placeholder that {@see \FetchIp()} returns and the
 * banlist caches so the lookup isn't retried on every render; it also
 * collapses to `null`.
 */
final class CountryFlag
{
    public const UNKNOWN = 'zz';

    public static function enabled(): bool
    {
        return !Config::getBool('banlist.nocountryfetch');
    }

    /**
     * Lowercase ISO 3166-1 alpha-2 code with a bundled flag image, or
     * `null` when the input is empty, malformed, the unknown
     * placeholder, or has no flag on disk.
     */
    public static function normalize(?string $code): ?string
    {
        $code = strtolower(trim((string) $code));
        if ($code === self::UNKNOWN || !preg_match('/^[a-z]{2}$/D', $code)) {
            return null;
        }
        return is_file(ROOT . 'images/country/' . $code . '.png') ? $code : null;
    }

    /**
     * Resolve the flag code for a ban row. Prefers the cached column
     * value; falls back to a local MaxMind lookup on `$ip` when the
     * column is empty. `$lookedUp` receives the raw lookup result
     * (including the `zz` placeholder) so the caller can cache it, or
     * `null` when no lookup ran.
     */
    public static function resolve(?string $stored, ?string $ip, ?string &$lookedUp = null): ?string
    {
        $lookedUp = null;
        $stored   = trim((string) $stored);
        if ($stored !== '') {
            return self::normalize($stored);
        }
        $ip = trim((string) $ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $lookedUp = \FetchIp($ip);
        return self::normalize($lookedUp);
    }

    public static function imageUrl(string $code): string
    {
        return 'images/country/' . $code . '.png';
    }

    /**
     * English display name for a normalised code ("fr" → "France").
     * Falls back to the uppercase code when ext-intl is missing.
     */
    public static function name(string $code): string
    {
        $upper = strtoupper($code);
        if (class_exists(\Locale::class)) {
            $name = \Locale::getDisplayRegion('und-' . $upper, 'en');
            if (is_string($name) && $name !== '' && $name !== $upper) {
                return $name;
            }
        }
        return $upper;
    }
}
