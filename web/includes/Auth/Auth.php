<?php

namespace Sbpp\Auth;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use PDO;
use Sbpp\Db\Database;
use Sbpp\Security\Crypto;

/**
 * Class Auth
 */
final class Auth
{
    private static ?Database $dbs = null;

    public static function init(Database $dbs): void
    {
        self::$dbs = $dbs;
    }

    /** Lazily probed: `login_tokens.aid` only exists once migration 814 ran. */
    private static ?bool $hasAidColumn = null;

    public static function login(int $aid, int $maxlife): void
    {
        $jti = self::generateJTI();

        $token = JWT::create($jti, $maxlife, $aid);
        // Every session is backed by a `login_tokens` row; verify() refuses
        // a token whose row is gone, which is how logout and password
        // changes revoke it server-side (#54).
        self::insertNewToken($jti, $aid);
        self::updateLastVisit($aid);

        self::setCookie($token->toString(), time() + $maxlife, Host::cookieDomain(), Host::isSecure());

        //Login / Logout requests will trigger GC routine
        self::gc();
    }

    public static function logout(): bool
    {
        $cookie = self::getJWTFromCookie();
        if (empty($cookie) || preg_match('/.*\..*\..*\./', $cookie)) {
            return false;
        }

        $token = self::parseCookie($cookie);
        if ($token !== null && JWT::validate($token)) {
            self::$dbs->query("DELETE FROM `:prefix_login_tokens` WHERE jti = :jti");
            self::$dbs->bind(':jti', (string) $token->claims()->get('jti'), PDO::PARAM_STR);
            self::$dbs->execute();
        }

        self::setCookie('', 1, Host::cookieDomain(), Host::isSecure());

        //Login / Logout requests will trigger GC routine
        self::gc();

        return true;
    }

    public static function verify(): ?Token
    {
        if (defined('SBPP_REST')) {
            return null;
        }

        $cookie = self::getJWTFromCookie();
        if (empty($cookie) || preg_match('/.*\..*\..*\./', $cookie)) {
            return null;
        }

        $token = self::parseCookie($cookie);
        if ($token === null || !JWT::validate($token)) {
            return null;
        }

        $jti = (string) $token->claims()->get('jti');
        $row = self::getTokenRow($jti);
        if ($row === null) {
            // Revoked (logout / password change / admin removed) or minted
            // before sessions were persisted.
            return null;
        }
        if (array_key_exists('aid', $row) && (int) $row['aid'] !== (int) $token->claims()->get('aid')) {
            return null;
        }

        self::updateLastAccessed($jti);
        return $token;
    }

    /**
     * End every browser session of an admin. Called when their password
     * changes, and when they are deactivated or deleted (#54). A no-op
     * until migration 814 adds `login_tokens.aid`.
     */
    public static function revokeAllForAdmin(int $aid): void
    {
        if ($aid <= 0 || !self::hasAidColumn()) {
            return;
        }

        self::$dbs->query("DELETE FROM `:prefix_login_tokens` WHERE aid = :aid");
        self::$dbs->bind(':aid', $aid, PDO::PARAM_INT);
        self::$dbs->execute();
    }

    /** Parse a cookie value, or null when it isn't a well-formed, unencrypted JWT. */
    private static function parseCookie(string $cookie): ?UnencryptedToken
    {
        try {
            $token = JWT::parse($cookie);
        } catch (\Lcobucci\JWT\Exception) {
            return null;
        }

        return $token instanceof UnencryptedToken ? $token : null;
    }

    private static function hasAidColumn(): bool
    {
        if (self::$hasAidColumn !== null) {
            return self::$hasAidColumn;
        }

        self::$dbs->query(
            'SELECT COUNT(*) AS c FROM information_schema.COLUMNS '
            . 'WHERE TABLE_SCHEMA = DATABASE() '
            . 'AND TABLE_NAME = :table '
            . "AND COLUMN_NAME = 'aid'"
        );
        self::$dbs->bind(':table', self::$dbs->getPrefix() . '_login_tokens');
        $row = self::$dbs->single();
        self::$hasAidColumn = is_array($row) && (int) ($row['c'] ?? 0) > 0;

        return self::$hasAidColumn;
    }

    private static function setCookie(string $data, int $lifetime, string $domain, bool $secure): void
    {
        setcookie('sbpp_auth', $data, [
            'expires' => $lifetime,
            'path' => '/',
            'domain' => $domain,
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    private static function gc(): void
    {
        self::$dbs->query(
            "DELETE FROM `:prefix_login_tokens` WHERE lastAccessed < UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 30 DAY))"
        );
        self::$dbs->execute();
    }

    private static function insertNewToken(string $jti, int $aid): void
    {
        // `secret` is a legacy NOT NULL UNIQUE column nothing reads; a random
        // value keeps the constraint satisfied.
        if (self::hasAidColumn()) {
            self::$dbs->query(
                "INSERT INTO `:prefix_login_tokens` (jti, aid, secret, lastAccessed) VALUES (:jti, :aid, :secret, UNIX_TIMESTAMP())"
            );
            self::$dbs->bind(':aid', $aid, PDO::PARAM_INT);
        } else {
            self::$dbs->query(
                "INSERT INTO `:prefix_login_tokens` (jti, secret, lastAccessed) VALUES (:jti, :secret, UNIX_TIMESTAMP())"
            );
        }
        self::$dbs->bind(':jti', $jti, PDO::PARAM_STR);
        self::$dbs->bind(':secret', Crypto::genSecret(), PDO::PARAM_STR);
        self::$dbs->execute();
    }

    private static function updateLastVisit(int $aid): void
    {
        self::$dbs->query("UPDATE `:prefix_admins` SET lastvisit = UNIX_TIMESTAMP() WHERE aid = :aid");
        self::$dbs->bind(':aid', $aid, PDO::PARAM_INT);
        self::$dbs->execute();
    }

    private static function updateLastAccessed(string $jti): void
    {
        self::$dbs->query("UPDATE `:prefix_login_tokens` SET lastAccessed = UNIX_TIMESTAMP() WHERE jti = :jti");
        self::$dbs->bind(':jti', $jti, PDO::PARAM_STR);
        self::$dbs->execute();
    }

    /** @return array<string, mixed>|null the session row, `aid` included once migration 814 ran */
    private static function getTokenRow(string $jti): ?array
    {
        $columns = self::hasAidColumn() ? 'jti, aid' : 'jti';
        self::$dbs->query("SELECT {$columns} FROM `:prefix_login_tokens` WHERE jti = :jti");
        self::$dbs->bind(':jti', $jti, PDO::PARAM_STR);
        $result = self::$dbs->single();
        return is_array($result) && $result !== [] ? $result : null;
    }

    private static function generateJTI(): string
    {
        do {
            $jti = Crypto::genJTI();
        } while (self::checkJTI($jti));

        return $jti;
    }

    private static function checkJTI(string $jti): bool
    {
        self::$dbs->query("SELECT 1 FROM `:prefix_login_tokens` WHERE jti = :jti");
        self::$dbs->bind(':jti', $jti, PDO::PARAM_STR);
        $result = self::$dbs->single();
        return !empty($result);
    }

    private static function getJWTFromCookie(): string
    {
        return is_string($_COOKIE['sbpp_auth'] ?? null) ? $_COOKIE['sbpp_auth'] : '';
    }
}

// Issue #1290 phase B: legacy global-name shim. Procedural code keeps
// using `\Auth` until the call-site sweep PR.
class_alias(\Sbpp\Auth\Auth::class, 'Auth');
