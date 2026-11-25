<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

/**
 * Device cookies (#106), after OWASP "Slow Down Online Guessing Attacks
 * with Device Cookies". A browser that signed in successfully as a user
 * gets `sbpp_device`, bound to that username's {@see LoginThrottle::nameKey()}.
 * Its failed attempts then count against the cookie (`d:` counter) instead
 * of the name's shared counter (`n:`), so when an attacker fills the
 * shared counter, the admin's own browser can still sign in.
 *
 * Value: `v1.<issued>.<nonce>.<mac>`, the MAC an HMAC-SHA256 over the
 * version, issue time, nonce and name key, with a key derived from
 * `SB_SECRET_KEY` (rotating it voids every device cookie, like sessions).
 * Nothing is stored server-side; the nonce only keys the `d:` counter.
 * The cookie grants nothing by itself: it only chooses which counter a
 * password attempt is charged to.
 */
final class DeviceCookie
{
    public const COOKIE = 'sbpp_device';
    public const LIFETIME = 180 * 24 * 60 * 60;

    private const VERSION = 'v1';

    /**
     * The nonce of a valid cookie for `$nameKey`, or null when the request
     * has none, it is forged, expired, or was issued for another name.
     */
    public static function nonceFor(string $nameKey, int $now): ?string
    {
        $raw = $_COOKIE[self::COOKIE] ?? null;
        if (!is_string($raw) || strlen($raw) > 200) {
            return null;
        }
        $parts = explode('.', $raw);
        if (count($parts) !== 4 || $parts[0] !== self::VERSION) {
            return null;
        }
        [, $issued, $nonce, $mac] = $parts;
        if (!ctype_digit($issued) || !preg_match('/^[A-Za-z0-9_-]{22}$/D', $nonce)) {
            return null;
        }
        $issuedAt = (int) $issued;
        if ($issuedAt > $now + 300 || $issuedAt + self::LIFETIME <= $now) {
            return null;
        }
        if (!hash_equals(self::mac($issued, $nonce, $nameKey), $mac)) {
            return null;
        }
        return $nonce;
    }

    /** Give this browser a device cookie for `$nameKey` (after a successful sign-in). */
    public static function issue(string $nameKey, int $now): void
    {
        $value = self::build($nameKey, $now, self::b64(random_bytes(16)));
        $_COOKIE[self::COOKIE] = $value;
        if (headers_sent()) {
            return;
        }
        setcookie(self::COOKIE, $value, [
            'expires'  => $now + self::LIFETIME,
            'path'     => '/',
            'domain'   => Host::cookieDomain(),
            'secure'   => Host::isSecure(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    /** Throttle key of a device nonce. */
    public static function counterKey(string $nonce): string
    {
        return 'd:' . hash('sha256', $nonce);
    }

    /** @internal public for tests */
    public static function build(string $nameKey, int $issued, string $nonce): string
    {
        $issuedStr = (string) $issued;
        return implode('.', [self::VERSION, $issuedStr, $nonce, self::mac($issuedStr, $nonce, $nameKey)]);
    }

    private static function mac(string $issued, string $nonce, string $nameKey): string
    {
        $data = self::VERSION . '|' . $issued . '|' . $nonce . '|' . $nameKey;
        return self::b64(hash_hmac('sha256', $data, self::key(), true));
    }

    private static function key(): string
    {
        $secret = JWT::signingKeyFromSecret(SB_SECRET_KEY)->contents();
        return hash_hkdf('sha256', $secret, 32, 'sbpp-device-cookie-v1');
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
