<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

use Sbpp\Db\Database;

/**
 * Per-address limit on password logins (#97), next to the per-account
 * lockout in `api_auth_login`. The account lockout alone let one client
 * try a password against every username without tripping anything.
 *
 * Fixed window: at most {@see limit()} unsuccessful attempts per address
 * per {@see WINDOW_SECONDS}. An attempt is counted before the password is
 * checked ({@see reserve()}) and given back when the login succeeds
 * ({@see release()}), so parallel requests can't all slip under the limit.
 *
 * The address is `REMOTE_ADDR`. Behind a reverse proxy it must be the
 * client's (the Docker image's `mod_remoteip` with `SBPP_TRUSTED_PROXIES`),
 * otherwise every visitor shares the proxy's counter. IPv6 addresses are
 * cut to their /64, the block one client usually controls.
 *
 * `SBPP_LOGIN_IP_LIMIT` (config.php or env) overrides the limit; `0`
 * turns the per-address limit off.
 */
final class LoginThrottle
{
    public const DEFAULT_LIMIT = 20;
    public const WINDOW_SECONDS = 15 * 60;

    /** Expired rows removed per login attempt, so GC stays cheap. */
    private const GC_BATCH = 100;

    public function __construct(private Database $dbs) {}

    public static function limit(): int
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
     * Key for an address: hex of the packed IPv4 address, or of the first
     * 8 bytes (/64) of an IPv6 one. Null when the address doesn't parse.
     */
    public static function key(string $ip): ?string
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
     * Count one login attempt from `$ip`. Returns the number of seconds
     * until the window ends when the address is over the limit (the
     * caller must refuse the login without checking the password), or
     * null when the attempt may go ahead.
     */
    public function reserve(string $ip, int $now): ?int
    {
        $limit = self::limit();
        $key = self::key($ip);
        if ($limit === 0 || $key === null) {
            return null;
        }

        $cutoff = $now - self::WINDOW_SECONDS;
        try {
            return $this->count($key, $limit, $now, $cutoff);
        } catch (\PDOException) {
            // The table is missing between uploading a release and running
            // the updater (migration 818). Fail open: the per-account
            // lockout still applies, and logins keep working until then.
            return null;
        }
    }

    private function count(string $key, int $limit, int $now, int $cutoff): ?int
    {
        $this->gc($cutoff);

        // One statement, so concurrent attempts can't overwrite each
        // other's count. `attempts` is assigned first and reads the old
        // `window_start`; `window_start` then reads its own old value.
        $this->dbs->query(
            'INSERT INTO `:prefix_login_throttle` (ip, attempts, window_start) VALUES (:ip, 1, :now)'
            . ' ON DUPLICATE KEY UPDATE'
            . ' attempts = IF(window_start <= :cutoff, 1, attempts + 1),'
            . ' window_start = IF(window_start <= :cutoff2, :now2, window_start)'
        );
        $this->dbs->bindMultiple([
            ':ip'      => $key,
            ':now'     => $now,
            ':cutoff'  => $cutoff,
            ':cutoff2' => $cutoff,
            ':now2'    => $now,
        ]);
        $this->dbs->execute();

        // Read back after the write: a concurrent attempt can only make
        // the count higher, never let this one through wrongly.
        $this->dbs->query('SELECT attempts, window_start FROM `:prefix_login_throttle` WHERE ip = :ip');
        $this->dbs->bind(':ip', $key);
        $row = $this->dbs->single();
        if (!is_array($row) || (int) $row['attempts'] <= $limit) {
            return null;
        }
        return max(1, (int) $row['window_start'] + self::WINDOW_SECONDS - $now);
    }

    /** Give back the attempt {@see reserve()} counted: the login succeeded. */
    public function release(string $ip): void
    {
        $key = self::key($ip);
        if (self::limit() === 0 || $key === null) {
            return;
        }
        try {
            $this->dbs->query(
                'UPDATE `:prefix_login_throttle` SET attempts = attempts - 1 WHERE ip = :ip AND attempts > 0'
            );
            $this->dbs->bind(':ip', $key);
            $this->dbs->execute();
        } catch (\PDOException) {
            // Same as reserve(): table not created yet.
        }
    }

    private function gc(int $cutoff): void
    {
        $this->dbs->query(
            'DELETE FROM `:prefix_login_throttle` WHERE window_start <= :cutoff LIMIT ' . self::GC_BATCH
        );
        $this->dbs->bind(':cutoff', $cutoff);
        $this->dbs->execute();
    }
}
