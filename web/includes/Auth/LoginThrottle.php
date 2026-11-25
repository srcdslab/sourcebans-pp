<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

use Sbpp\Db\Database;

/**
 * Failed sign-in counters (#97, #106), one row per key in
 * `:prefix_auth_throttle`:
 *
 * - `ip:<address>`: password logins from one client address (IPv6 cut
 *   to its /64), {@see ipLimit()} per {@see WINDOW_SECONDS}.
 * - `n:<name>`: password logins for one username from clients without a
 *   device cookie for it ({@see DeviceCookie}), {@see ACCOUNT_LIMIT} per
 *   window. Keyed on the submitted name, so unknown names lock exactly
 *   like real ones and `m=locked` says nothing about whether the account
 *   exists.
 * - `d:<device>`: password logins from one browser holding a device
 *   cookie for that name, {@see ACCOUNT_LIMIT} per window. The admin's
 *   usual browser keeps its own budget while the name is locked for
 *   everyone else: an attacker can't lock the real admin out.
 * - `lpi:<address>` / `lpa:<aid>`: password reset requests.
 *
 * Every attempt takes its slot in one atomic upsert *before* the secret
 * is checked ({@see hit()}) and a successful login gives it back
 * ({@see release()}), so parallel requests can't slip under a limit.
 *
 * The address is `REMOTE_ADDR`. Behind a reverse proxy it must be the
 * client's (the Docker image's `mod_remoteip` with `SBPP_TRUSTED_PROXIES`),
 * otherwise every visitor shares the proxy's counter.
 *
 * A missing table raises {@see ThrottleUnavailable}: callers refuse the
 * sign-in. Pre-#106 it failed open, so a panel that never ran migration
 * 818 had no limit at all and nothing said so.
 */
final class LoginThrottle
{
    public const DEFAULT_LIMIT = 20;
    public const ACCOUNT_LIMIT = 5;
    public const WINDOW_SECONDS = 15 * 60;

    public const RESET_IP_LIMIT = 5;
    public const RESET_ACCOUNT_LIMIT = 3;
    public const RESET_WINDOW_SECONDS = 60 * 60;

    /** Expired rows removed per hit, so GC stays cheap. */
    private const GC_BATCH = 100;

    /** @var array{charset: string, collation: string}|null */
    private static ?array $nameCollation = null;

    public function __construct(private Database $dbs) {}

    /** Per-address limit: `SBPP_LOGIN_IP_LIMIT` (config.php or env), `0` turns it off. */
    public static function ipLimit(): int
    {
        if (!defined('SBPP_LOGIN_IP_LIMIT')) {
            return self::DEFAULT_LIMIT;
        }
        $value = constant('SBPP_LOGIN_IP_LIMIT');
        if (is_int($value)) {
            return max(0, $value);
        }
        if (is_string($value) && trim($value) !== '' && ctype_digit(trim($value))) {
            return (int) trim($value);
        }
        return self::DEFAULT_LIMIT;
    }

    /**
     * Hex of the packed IPv4 address, or of the first 8 bytes (/64) of an
     * IPv6 one. Null when the address doesn't parse.
     */
    public static function addressKey(string $ip): ?string
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        if (strlen($packed) === 16) {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) is the IPv4 client.
            if (str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
                return bin2hex(substr($packed, 12));
            }
            return bin2hex(substr($packed, 0, 8));
        }
        return bin2hex($packed);
    }

    /**
     * The username as `:prefix_admins.user` compares it: the column's
     * collation weight string, hex. `Admin`, `ADMIN`, `ádmin` and
     * `admin ` all reach the same account through `WHERE user = :user`,
     * so they must share one counter, or rotating variants would give
     * unlimited guesses on one account.
     *
     * Pass the stored name when the lookup matched and the submitted name
     * otherwise: under a NO PAD collation `admin ` is not `admin`, but the
     * trailing spaces are stripped for unknown names so the two still
     * share a key.
     *
     * @throws ThrottleUnavailable
     */
    public function nameKey(string $name, bool $stored): string
    {
        $collation = $this->nameCollation();
        if (!$stored) {
            $name = rtrim($name, ' ');
        }
        try {
            $this->dbs->query(sprintf(
                'SELECT HEX(WEIGHT_STRING(CONVERT(:name USING %s) COLLATE %s)) AS w',
                $collation['charset'],
                $collation['collation'],
            ));
            $this->dbs->bind(':name', $name);
            $row = $this->dbs->single();
        } catch (\PDOException $e) {
            throw new ThrottleUnavailable('username key: ' . $e->getMessage(), 0, $e);
        }
        $weight = is_array($row) ? (string) ($row['w'] ?? '') : '';
        return hash('sha256', $weight);
    }

    /**
     * Count one attempt against `$key`. The returned hit says whether the
     * caller must refuse it (without checking the secret).
     *
     * @throws ThrottleUnavailable when the table is missing (updater not run)
     */
    public function hit(string $key, int $limit, int $window, int $now): ThrottleHit
    {
        if ($limit <= 0) {
            return new ThrottleHit(0, 0, 0);
        }
        try {
            $this->gc($now);

            // One statement, so concurrent attempts can't overwrite each
            // other's count. `attempts` is assigned first and reads the old
            // `expires`; `expires` then reads its own old value.
            $this->dbs->query(
                'INSERT INTO `:prefix_auth_throttle` (throttle_key, attempts, expires) VALUES (:k, 1, :exp)'
                . ' ON DUPLICATE KEY UPDATE'
                . ' attempts = IF(expires <= :now, 1, attempts + 1),'
                . ' expires = IF(expires <= :now2, :exp2, expires)'
            );
            $this->dbs->bindMultiple([
                ':k'    => $key,
                ':exp'  => $now + $window,
                ':now'  => $now,
                ':now2' => $now,
                ':exp2' => $now + $window,
            ]);
            $this->dbs->execute();

            // Read back after the write: a concurrent attempt can only make
            // the count higher, never let this one through wrongly.
            $this->dbs->query('SELECT attempts, expires FROM `:prefix_auth_throttle` WHERE throttle_key = :k');
            $this->dbs->bind(':k', $key);
            $row = $this->dbs->single();
        } catch (\PDOException $e) {
            throw new ThrottleUnavailable('auth_throttle: ' . $e->getMessage(), 0, $e);
        }

        if (!is_array($row)) {
            return new ThrottleHit(1, $limit, 0);
        }
        return new ThrottleHit((int) $row['attempts'], $limit, max(1, (int) $row['expires'] - $now));
    }

    /** Give back the attempt {@see hit()} counted: the sign-in succeeded. */
    public function release(string $key): void
    {
        try {
            $this->dbs->query(
                'UPDATE `:prefix_auth_throttle` SET attempts = attempts - 1 WHERE throttle_key = :k AND attempts > 0'
            );
            $this->dbs->bind(':k', $key);
            $this->dbs->execute();
        } catch (\PDOException) {
            // hit() already refused the sign-in if the table were missing.
        }
    }

    /** @return array{charset: string, collation: string} */
    private function nameCollation(): array
    {
        if (self::$nameCollation !== null) {
            return self::$nameCollation;
        }
        try {
            $this->dbs->query(
                'SELECT CHARACTER_SET_NAME AS cs, COLLATION_NAME AS co FROM information_schema.COLUMNS'
                . " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = 'user'"
            );
            $this->dbs->bind(':t', $this->dbs->getPrefix() . '_admins');
            $row = $this->dbs->single();
        } catch (\PDOException $e) {
            throw new ThrottleUnavailable('admins.user collation: ' . $e->getMessage(), 0, $e);
        }
        $charset = is_array($row) ? (string) ($row['cs'] ?? '') : '';
        $collation = is_array($row) ? (string) ($row['co'] ?? '') : '';
        // Interpolated into SQL (CONVERT/COLLATE take no placeholders):
        // identifiers only.
        if (!preg_match('/^[A-Za-z0-9_]+$/D', $charset) || !preg_match('/^[A-Za-z0-9_]+$/D', $collation)) {
            throw new ThrottleUnavailable('admins.user collation not found');
        }
        return self::$nameCollation = ['charset' => $charset, 'collation' => $collation];
    }

    /** Tests switch DB_PREFIX / schemas; drop the cached collation. */
    public static function clearCache(): void
    {
        self::$nameCollation = null;
    }

    private function gc(int $now): void
    {
        $this->dbs->query('DELETE FROM `:prefix_auth_throttle` WHERE expires <= :now LIMIT ' . self::GC_BATCH);
        $this->dbs->bind(':now', $now);
        $this->dbs->execute();
    }
}
