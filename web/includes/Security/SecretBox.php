<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Security;

use Sbpp\Auth\JWT;

/**
 * Encrypts small secrets stored in the database (TOTP seeds, #107) with
 * libsodium's secretbox (XSalsa20-Poly1305). The key is derived from
 * `SB_SECRET_KEY` with HKDF and a per-purpose label, so a database dump
 * alone doesn't give the secrets away.
 *
 * Rotating `SB_SECRET_KEY` makes existing ciphertexts unreadable:
 * {@see open()} returns null and callers must treat the secret as lost
 * (recovery codes are hashed, not encrypted, and keep working).
 */
final class SecretBox
{
    private const PREFIX = 'sb1:';

    public static function seal(string $plaintext, string $purpose): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($plaintext, $nonce, self::key($purpose));
        return self::PREFIX . base64_encode($nonce . $cipher);
    }

    /** The plaintext, or null when the value is malformed, tampered with or sealed under another key. */
    public static function open(string $sealed, string $purpose): ?string
    {
        if (!str_starts_with($sealed, self::PREFIX)) {
            return null;
        }
        $raw = base64_decode(substr($sealed, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            return null;
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open($cipher, $nonce, self::key($purpose));
        return $plain === false ? null : $plain;
    }

    private static function key(string $purpose): string
    {
        $secret = JWT::signingKeyFromSecret(SB_SECRET_KEY)->contents();
        return hash_hkdf('sha256', $secret, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'sbpp-secretbox-v1:' . $purpose);
    }
}
