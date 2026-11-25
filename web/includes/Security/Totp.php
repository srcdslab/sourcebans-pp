<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Security;

/**
 * TOTP (RFC 6238 over RFC 4226 HOTP): HMAC-SHA1, 6 digits, 30-second steps,
 * the parameters every authenticator app supports (#107). Pure functions:
 * replay protection (a step is accepted once) lives in
 * {@see \Sbpp\Auth\TwoFactor}, which stores the last accepted step.
 */
final class Totp
{
    public const DIGITS = 6;
    public const PERIOD = 30;
    /** Steps accepted either side of now, for clock drift (±30 s). */
    public const WINDOW = 1;
    /** 160-bit secret, the size RFC 4226 recommends for HMAC-SHA1. */
    public const SECRET_BYTES = 20;

    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** A new random secret, base32 (32 characters, no padding). */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(self::SECRET_BYTES));
    }

    public static function step(int $now): int
    {
        return intdiv($now, self::PERIOD);
    }

    /** The code for `$step` (RFC 4226 dynamic truncation). */
    public static function code(string $base32Secret, int $step): string
    {
        $key = self::base32Decode($base32Secret);
        if ($key === null || $key === '') {
            throw new \InvalidArgumentException('Invalid TOTP secret.');
        }
        $hmac = hash_hmac('sha1', pack('J', $step), $key, true);
        $offset = ord($hmac[19]) & 0x0f;
        $binary = ((ord($hmac[$offset]) & 0x7f) << 24)
            | (ord($hmac[$offset + 1]) << 16)
            | (ord($hmac[$offset + 2]) << 8)
            | ord($hmac[$offset + 3]);
        return str_pad((string) ($binary % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * The step `$code` matches within the window around `$now`, newest
     * first, or null. Steps at or before `$afterStep` are skipped: they
     * were already used. Every candidate is compared, constant-time.
     */
    public static function matchStep(string $base32Secret, string $code, int $now, int $afterStep = -1): ?int
    {
        $code = self::normalizeCode($code);
        if ($code === null) {
            return null;
        }
        $current = self::step($now);
        $found = null;
        for ($step = $current + self::WINDOW; $step >= $current - self::WINDOW; $step--) {
            if ($step < 0) {
                continue;
            }
            $match = hash_equals(self::code($base32Secret, $step), $code);
            if ($match && $step > $afterStep && $found === null) {
                $found = $step;
            }
        }
        return $found;
    }

    /** Digits only (spaces and dashes typed by users removed), or null. */
    public static function normalizeCode(string $code): ?string
    {
        $code = str_replace([' ', '-'], '', trim($code));
        return preg_match('/^\d{' . self::DIGITS . '}$/D', $code) === 1 ? $code : null;
    }

    /** `otpauth://` URI the authenticator app reads from the QR code. */
    public static function provisioningUri(string $issuer, string $account, string $base32Secret): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        return 'otpauth://totp/' . $label . '?' . http_build_query([
            'secret'    => $base32Secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::BASE32[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }
        return $out;
    }

    /** Decode base32 (case-insensitive, spaces and padding ignored), or null when invalid. */
    public static function base32Decode(string $text): ?string
    {
        $text = strtoupper(str_replace([' ', '='], '', $text));
        if ($text === '' || strspn($text, self::BASE32) !== strlen($text)) {
            return null;
        }
        $bits = '';
        foreach (str_split($text) as $char) {
            $bits .= str_pad(decbin((int) strpos(self::BASE32, $char)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr((int) bindec($byte));
            }
        }
        return $out;
    }
}
