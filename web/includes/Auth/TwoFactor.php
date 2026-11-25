<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

use Sbpp\Config;
use Sbpp\Db\Database;
use Sbpp\Security\SecretBox;
use Sbpp\Security\Totp;

/**
 * Two-factor authentication (TOTP, #107; passkeys as a second factor, #108).
 *
 * Every sign-in method (password, Steam) ends in {@see completePrimary()}.
 * An admin with 2FA gets no session there: the browser gets a short-lived
 * pending step (`sbpp_2fa` cookie, a random token whose hash is a
 * `:prefix_auth_pending` row) and must send a code to
 * {@see verifyPending()}. An admin the `auth.2fa.require` setting covers
 * but who has no 2FA yet gets an `enroll` pending step instead and must set
 * it up before getting a session.
 *
 * Storage:
 * - `:prefix_admin_totp`: one row per admin, the base32 secret sealed with
 *   {@see SecretBox}, `confirmed_at` (NULL while being set up) and the last
 *   accepted time step (a code is accepted once).
 * - `:prefix_admin_recovery_codes`: SHA-256 of single-use recovery codes.
 *   80 random bits each, so a plain hash is enough, and they survive an
 *   `SB_SECRET_KEY` rotation that makes the TOTP secret unreadable.
 */
final class TwoFactor
{
    public const SETTING = 'auth.2fa.require';
    public const REQUIRE_OFF = 'off';
    public const REQUIRE_OWNERS = 'owners';
    public const REQUIRE_ALL = 'all';

    public const PENDING_COOKIE = 'sbpp_2fa';
    public const PENDING_TTL = 10 * 60;
    /** Wrong codes allowed on one pending step before it is discarded. */
    public const PENDING_ATTEMPTS = 5;
    /** Wrong codes allowed per account per {@see LoginThrottle::WINDOW_SECONDS}, across pending steps. */
    public const ACCOUNT_LIMIT = 10;

    public const RECOVERY_CODES = 10;

    public const PURPOSE_VERIFY = 'verify';
    public const PURPOSE_ENROLL = 'enroll';

    private const SECRET_PURPOSE = 'totp';

    public function __construct(private Database $dbs) {}

    // -- Policy ---------------------------------------------------------

    public static function requirement(): string
    {
        $value = (string) Config::get(self::SETTING);
        return in_array($value, [self::REQUIRE_OWNERS, self::REQUIRE_ALL], true) ? $value : self::REQUIRE_OFF;
    }

    /** Whether the `auth.2fa.require` setting covers this admin. */
    public function isRequiredFor(int $aid): bool
    {
        return match (self::requirement()) {
            self::REQUIRE_ALL    => true,
            self::REQUIRE_OWNERS => $this->isOwner($aid),
            default              => false,
        };
    }

    /**
     * Whether the admin has any second factor: TOTP, or a passkey (#108).
     * This, not {@see isEnrolled()}, decides whether a sign-in needs a
     * second step and whether `auth.2fa.require` is met.
     */
    public function hasSecondFactor(int $aid): bool
    {
        return $this->isEnrolled($aid) || (new Passkeys($this->dbs))->count($aid) > 0;
    }

    /** Whether TOTP is on (a confirmed authenticator app). */
    public function isEnrolled(int $aid): bool
    {
        $this->dbs->query('SELECT 1 FROM `:prefix_admin_totp` WHERE aid = :aid AND confirmed_at IS NOT NULL');
        $this->dbs->bind(':aid', $aid);
        return (bool) $this->dbs->single();
    }

    /** Unused recovery codes left. */
    public function recoveryCodesLeft(int $aid): int
    {
        $this->dbs->query('SELECT COUNT(*) AS c FROM `:prefix_admin_recovery_codes` WHERE aid = :aid AND used_at IS NULL');
        $this->dbs->bind(':aid', $aid);
        $row = $this->dbs->single();
        return is_array($row) ? (int) $row['c'] : 0;
    }

    private function isOwner(int $aid): bool
    {
        $this->dbs->query(
            'SELECT adm.extraflags AS ef, wg.flags AS gf FROM `:prefix_admins` AS adm'
            . ' LEFT JOIN `:prefix_groups` AS wg ON adm.gid = wg.gid WHERE adm.aid = :aid'
        );
        $this->dbs->bind(':aid', $aid);
        $row = $this->dbs->single();
        if (!is_array($row)) {
            return false;
        }
        $flags = (int) ($row['ef'] ?? 0) | (int) ($row['gf'] ?? 0);
        return ($flags & \WebPermission::Owner->value) !== 0;
    }

    // -- Sign-in --------------------------------------------------------

    /**
     * The primary sign-in (password or Steam) succeeded for `$aid`. Either
     * starts the session, or opens a pending second step. Returns the
     * query string to send the browser to (`?…`).
     */
    public function completePrimary(int $aid, int $maxlife, string $redirect): string
    {
        if ($this->hasSecondFactor($aid)) {
            $this->openPending($aid, self::PURPOSE_VERIFY, $maxlife, $redirect);
            return '?p=login&step=2fa';
        }
        if ($this->isRequiredFor($aid)) {
            $this->openPending($aid, self::PURPOSE_ENROLL, $maxlife, $redirect);
            return '?p=login&step=enroll';
        }
        Auth::login($aid, $maxlife);
        return '?' . $redirect;
    }

    /**
     * A sign-in that is already two factors on its own: a passkey with
     * user verification (#108). Starts the session; never call
     * `Auth::login()` from a sign-in path directly (see AGENTS.md).
     */
    public function completeStrong(int $aid, int $maxlife): void
    {
        Auth::login($aid, $maxlife);
    }

    /**
     * Passkey options for this browser's `verify` pending step: only the
     * pending admin's passkeys (#108). Null without such a step.
     *
     * @return array<string, mixed>|null
     */
    public function pendingPasskeyOptions(): ?array
    {
        $pending = $this->pending();
        if ($pending === null || $pending['purpose'] !== self::PURPOSE_VERIFY || !Passkeys::available()) {
            return null;
        }
        $passkeys = new Passkeys($this->dbs);
        if ($passkeys->count($pending['aid']) === 0) {
            return null;
        }
        return $passkeys->requestOptions(Passkeys::PURPOSE_SECOND, $pending['aid']);
    }

    /**
     * Answer this browser's `verify` pending step with a passkey (#108).
     * Counted like a code.
     *
     * @param array<string, mixed> $credential
     * @return array{ok: true, redirect: string}|array{ok: false, error: string, retry_after?: int}
     */
    public function verifyPendingWithPasskey(array $credential, int $now): array
    {
        $pending = $this->pending();
        if ($pending === null || $pending['purpose'] !== self::PURPOSE_VERIFY) {
            return ['ok' => false, 'error' => 'expired'];
        }
        $gate = $this->takeAttempt($pending, $now);
        if ($gate !== null) {
            return $gate;
        }
        $aid = (new Passkeys($this->dbs))->finishAssertion(Passkeys::PURPOSE_SECOND, $credential, $pending['aid'], $now);
        if ($aid !== $pending['aid']) {
            return ['ok' => false, 'error' => 'invalid_passkey'];
        }
        $this->succeed($pending);
        return ['ok' => true, 'redirect' => '?' . $pending['redirect']];
    }

    /**
     * The pending step of this browser, or null when it has none or it
     * expired.
     *
     * @return array{token_hash: string, aid: int, purpose: string, maxlife: int, redirect: string, attempts: int}|null
     */
    public function pending(): ?array
    {
        $token = $_COOKIE[self::PENDING_COOKIE] ?? null;
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $token)) {
            return null;
        }
        $hash = hash('sha256', $token);
        $this->dbs->query(
            'SELECT token_hash, aid, purpose, maxlife, redirect, attempts FROM `:prefix_auth_pending`'
            . ' WHERE token_hash = :h AND expires > :now'
        );
        $this->dbs->bind(':h', $hash);
        $this->dbs->bind(':now', time());
        $row = $this->dbs->single();
        if (!is_array($row) || !hash_equals((string) $row['token_hash'], $hash)) {
            return null;
        }
        return [
            'token_hash' => (string) $row['token_hash'],
            'aid'        => (int) $row['aid'],
            'purpose'    => (string) $row['purpose'],
            'maxlife'    => (int) $row['maxlife'],
            'redirect'   => (string) $row['redirect'],
            'attempts'   => (int) $row['attempts'],
        ];
    }

    /** Abandon this browser's pending step (cancel, or after success). */
    public function closePending(): void
    {
        $token = $_COOKIE[self::PENDING_COOKIE] ?? null;
        if (is_string($token) && $token !== '') {
            $this->dbs->query('DELETE FROM `:prefix_auth_pending` WHERE token_hash = :h');
            $this->dbs->bind(':h', hash('sha256', $token));
            $this->dbs->execute();
        }
        unset($_COOKIE[self::PENDING_COOKIE]);
        $this->setPendingCookie('', 1);
    }

    /**
     * Check a code (TOTP or recovery) for this browser's `verify` pending
     * step. On success the session starts and the result carries the
     * query string to go to.
     *
     * @return array{ok: true, redirect: string, recovery_used: bool}|array{ok: false, error: string, retry_after?: int}
     */
    public function verifyPending(string $code, int $now): array
    {
        $pending = $this->pending();
        if ($pending === null || $pending['purpose'] !== self::PURPOSE_VERIFY) {
            return ['ok' => false, 'error' => 'expired'];
        }
        $gate = $this->takeAttempt($pending, $now);
        if ($gate !== null) {
            return $gate;
        }

        $aid = $pending['aid'];
        $recovery = false;
        if (!$this->checkTotp($aid, $code, $now)) {
            if (!$this->useRecoveryCode($aid, $code, $now)) {
                return ['ok' => false, 'error' => 'invalid'];
            }
            $recovery = true;
        }

        $this->succeed($pending);
        return ['ok' => true, 'redirect' => '?' . $pending['redirect'], 'recovery_used' => $recovery];
    }

    /**
     * Confirm the first code of an `enroll` pending step. On success 2FA is
     * on, the session starts, and the recovery codes are returned (shown
     * once).
     *
     * @return array{ok: true, redirect: string, recovery_codes: list<string>}|array{ok: false, error: string, retry_after?: int}
     */
    public function confirmPendingEnrolment(string $code, int $now): array
    {
        $pending = $this->pending();
        if ($pending === null || $pending['purpose'] !== self::PURPOSE_ENROLL) {
            return ['ok' => false, 'error' => 'expired'];
        }
        $gate = $this->takeAttempt($pending, $now);
        if ($gate !== null) {
            return $gate;
        }
        $codes = $this->confirmSetup($pending['aid'], $code, $now);
        if ($codes === null) {
            return ['ok' => false, 'error' => 'invalid'];
        }
        $this->succeed($pending);
        return ['ok' => true, 'redirect' => '?' . $pending['redirect'], 'recovery_codes' => $codes];
    }

    /**
     * Count one code attempt against the pending step, the account and the
     * address, before the code is checked. Null when the attempt may go on.
     *
     * @param array{token_hash: string, aid: int} $pending
     * @return array{ok: false, error: string, retry_after?: int}|null
     */
    private function takeAttempt(array $pending, int $now): ?array
    {
        $this->dbs->query(
            'UPDATE `:prefix_auth_pending` SET attempts = attempts + 1'
            . ' WHERE token_hash = :h AND attempts < :max AND expires > :now'
        );
        $this->dbs->bindMultiple([':h' => $pending['token_hash'], ':max' => self::PENDING_ATTEMPTS, ':now' => $now]);
        $this->dbs->execute();
        if ($this->dbs->rowCount() === 0) {
            // Out of attempts: start the sign-in over.
            $this->closePending();
            return ['ok' => false, 'error' => 'expired'];
        }

        $throttle = new LoginThrottle($this->dbs);
        try {
            $hit = $throttle->hit('2fa:' . $pending['aid'], self::ACCOUNT_LIMIT, LoginThrottle::WINDOW_SECONDS, $now);
            if ($hit->blocked()) {
                if ($hit->trippedNow()) {
                    \Sbpp\Log::add(
                        \LogType::Warning,
                        'Two-factor locked',
                        sprintf(
                            '%d wrong two-factor codes for admin aid %d in %d minutes: the password (or Steam sign-in) of this admin'
                            . ' is probably known to someone else. Code entry is refused for up to %d minutes.',
                            self::ACCOUNT_LIMIT,
                            $pending['aid'],
                            intdiv(LoginThrottle::WINDOW_SECONDS, 60),
                            max(1, (int) ceil($hit->retryAfter / 60)),
                        ),
                    );
                }
                return ['ok' => false, 'error' => 'locked', 'retry_after' => $hit->retryAfter];
            }
            $ipKey = LoginThrottle::addressKey((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
            if ($ipKey !== null && LoginThrottle::ipLimit() > 0) {
                $ipHit = $throttle->hit('ip:' . $ipKey, LoginThrottle::ipLimit(), LoginThrottle::WINDOW_SECONDS, $now);
                if ($ipHit->blocked()) {
                    return ['ok' => false, 'error' => 'locked', 'retry_after' => $ipHit->retryAfter];
                }
            }
        } catch (ThrottleUnavailable $e) {
            error_log(sprintf(
                '[sbpp] two-factor code refused, %s: %s',
                $e->tableMissing ? 'the sign-in counter table is missing (run the updater)' : 'the sign-in counters could not be read or written',
                $e->getMessage(),
            ));
            return ['ok' => false, 'error' => $e->tableMissing ? 'unavailable' : 'signin_error'];
        }
        return null;
    }

    /** @param array{aid: int, maxlife: int} $pending */
    private function succeed(array $pending): void
    {
        $throttle = new LoginThrottle($this->dbs);
        $throttle->release('2fa:' . $pending['aid']);
        $ipKey = LoginThrottle::addressKey((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        if ($ipKey !== null && LoginThrottle::ipLimit() > 0) {
            $throttle->release('ip:' . $ipKey);
        }
        $this->closePending();
        Auth::login($pending['aid'], $pending['maxlife']);
    }

    private function openPending(int $aid, string $purpose, int $maxlife, string $redirect): void
    {
        $now = time();
        $this->dbs->query('DELETE FROM `:prefix_auth_pending` WHERE expires <= :now LIMIT 100');
        $this->dbs->bind(':now', $now);
        $this->dbs->execute();

        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->dbs->query(
            'INSERT INTO `:prefix_auth_pending` (token_hash, aid, purpose, maxlife, redirect, attempts, expires)'
            . ' VALUES (:h, :aid, :purpose, :maxlife, :redirect, 0, :expires)'
        );
        $this->dbs->bindMultiple([
            ':h'        => hash('sha256', $token),
            ':aid'      => $aid,
            ':purpose'  => $purpose,
            ':maxlife'  => $maxlife,
            ':redirect' => mb_substr($redirect, 0, 255),
            ':expires'  => $now + self::PENDING_TTL,
        ]);
        $this->dbs->execute();

        $_COOKIE[self::PENDING_COOKIE] = $token;
        $this->setPendingCookie($token, $now + self::PENDING_TTL);
    }

    private function setPendingCookie(string $value, int $expires): void
    {
        if (headers_sent()) {
            return;
        }
        setcookie(self::PENDING_COOKIE, $value, [
            'expires'  => $expires,
            'path'     => '/',
            'domain'   => Host::cookieDomain(),
            'secure'   => Host::isSecure(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    // -- Codes ----------------------------------------------------------

    /**
     * Check a TOTP code against the admin's confirmed secret. A step is
     * accepted once: the `last_step` update is the atomic gate, so two
     * requests replaying the same code can't both pass.
     */
    public function checkTotp(int $aid, string $code, int $now): bool
    {
        $row = $this->totpRow($aid);
        if ($row === null || $row['confirmed_at'] === null) {
            return false;
        }
        $secret = SecretBox::open($row['secret'], self::SECRET_PURPOSE);
        if ($secret === null) {
            error_log('[sbpp] two-factor secret of admin aid ' . $aid . ' is unreadable (SB_SECRET_KEY changed?); a recovery code still works');
            return false;
        }
        $step = Totp::matchStep($secret, $code, $now, $row['last_step']);
        if ($step === null) {
            return false;
        }
        $this->dbs->query('UPDATE `:prefix_admin_totp` SET last_step = :step WHERE aid = :aid AND last_step < :step2');
        $this->dbs->bindMultiple([':step' => $step, ':aid' => $aid, ':step2' => $step]);
        $this->dbs->execute();
        return $this->dbs->rowCount() === 1;
    }

    /** Use up one recovery code. Compared in PHP, byte-exact (see AGENTS.md). */
    public function useRecoveryCode(int $aid, string $code, int $now): bool
    {
        $normalized = self::normalizeRecoveryCode($code);
        if ($normalized === null) {
            return false;
        }
        $hash = hash('sha256', $normalized);
        $this->dbs->query('SELECT id, code_hash FROM `:prefix_admin_recovery_codes` WHERE aid = :aid AND used_at IS NULL');
        $this->dbs->bind(':aid', $aid);
        $match = null;
        foreach ($this->dbs->resultset() as $row) {
            if (hash_equals((string) $row['code_hash'], $hash) && $match === null) {
                $match = (int) $row['id'];
            }
        }
        if ($match === null) {
            return false;
        }
        $this->dbs->query('UPDATE `:prefix_admin_recovery_codes` SET used_at = :now WHERE id = :id AND used_at IS NULL');
        $this->dbs->bindMultiple([':now' => $now, ':id' => $match]);
        $this->dbs->execute();
        if ($this->dbs->rowCount() !== 1) {
            return false;
        }
        \Sbpp\Log::add(
            \LogType::Warning,
            'Two-factor recovery code used',
            sprintf('A recovery code was used for admin aid %d; %d left.', $aid, $this->recoveryCodesLeft($aid)),
        );
        return true;
    }

    /** `XXXX-XXXX-XXXX-XXXX` typed in any case, with or without dashes/spaces. */
    public static function normalizeRecoveryCode(string $code): ?string
    {
        $code = strtoupper(str_replace([' ', '-'], '', trim($code)));
        return preg_match('/^[A-Z2-7]{16}$/D', $code) === 1 ? $code : null;
    }

    // -- Setup ----------------------------------------------------------

    /**
     * Start (or restart) setting up 2FA: a new secret, stored sealed and
     * unconfirmed. Null when 2FA is already on for this admin.
     *
     * @return array{secret: string, uri: string}|null
     */
    public function beginSetup(int $aid, string $accountName): ?array
    {
        if ($this->isEnrolled($aid)) {
            return null;
        }
        $secret = Totp::generateSecret();
        $this->dbs->query(
            'INSERT INTO `:prefix_admin_totp` (aid, secret, confirmed_at, last_step, created) VALUES (:aid, :s, NULL, -1, :now)'
            . ' ON DUPLICATE KEY UPDATE secret = IF(confirmed_at IS NULL, :s2, secret), last_step = IF(confirmed_at IS NULL, -1, last_step)'
        );
        $sealed = SecretBox::seal($secret, self::SECRET_PURPOSE);
        $this->dbs->bindMultiple([':aid' => $aid, ':s' => $sealed, ':now' => time(), ':s2' => $sealed]);
        $this->dbs->execute();

        return ['secret' => $secret, 'uri' => Totp::provisioningUri(self::issuer(), $accountName, $secret)];
    }

    /**
     * Confirm setup with a first code. Returns the new recovery codes, or
     * null when the code is wrong or no setup is in progress.
     *
     * @return list<string>|null
     */
    public function confirmSetup(int $aid, string $code, int $now): ?array
    {
        $row = $this->totpRow($aid);
        if ($row === null || $row['confirmed_at'] !== null) {
            return null;
        }
        $secret = SecretBox::open($row['secret'], self::SECRET_PURPOSE);
        if ($secret === null) {
            return null;
        }
        $step = Totp::matchStep($secret, $code, $now, $row['last_step']);
        if ($step === null) {
            return null;
        }
        $this->dbs->query(
            'UPDATE `:prefix_admin_totp` SET confirmed_at = :now, last_step = :step WHERE aid = :aid AND confirmed_at IS NULL'
        );
        $this->dbs->bindMultiple([':now' => $now, ':step' => $step, ':aid' => $aid]);
        $this->dbs->execute();
        if ($this->dbs->rowCount() !== 1) {
            return null;
        }
        $codes = $this->regenerateRecoveryCodes($aid);
        \Sbpp\Log::add(\LogType::Message, 'Two-factor enabled', sprintf('Two-factor authentication was turned on for admin aid %d.', $aid));
        return $codes;
    }

    /**
     * Replace every recovery code of the admin with new ones (shown once).
     *
     * @return list<string>
     */
    public function regenerateRecoveryCodes(int $aid): array
    {
        $this->dbs->query('DELETE FROM `:prefix_admin_recovery_codes` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $this->dbs->execute();

        $codes = [];
        for ($i = 0; $i < self::RECOVERY_CODES; $i++) {
            // 10 random bytes = 80 bits = 16 base32 characters.
            $raw = Totp::base32Encode(random_bytes(10));
            $codes[] = implode('-', str_split($raw, 4));
            $this->dbs->query('INSERT INTO `:prefix_admin_recovery_codes` (aid, code_hash, used_at) VALUES (:aid, :h, NULL)');
            $this->dbs->bindMultiple([':aid' => $aid, ':h' => hash('sha256', $raw)]);
            $this->dbs->execute();
        }
        return $codes;
    }

    /**
     * Remove every second factor of an admin: an Owner's reset, or the
     * admin being deleted. TOTP, recovery codes, pending steps, passkeys.
     */
    public function resetAll(int $aid): void
    {
        $this->disable($aid);
        (new Passkeys($this->dbs))->removeAll($aid);
    }

    /** Turn TOTP off for an admin (recovery codes and pending steps go too). */
    public function disable(int $aid): void
    {
        $this->dbs->query('DELETE FROM `:prefix_admin_totp` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $this->dbs->execute();
        $this->dbs->query('DELETE FROM `:prefix_admin_recovery_codes` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $this->dbs->execute();
        $this->dbs->query('DELETE FROM `:prefix_auth_pending` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $this->dbs->execute();
    }

    /** Issuer label shown in the authenticator app. */
    public static function issuer(): string
    {
        $host = (string) (parse_url(Host::panelUrl(), PHP_URL_HOST) ?: 'SourceBans++');
        return 'SourceBans++ (' . $host . ')';
    }

    /** @return array{secret: string, confirmed_at: int|null, last_step: int}|null */
    private function totpRow(int $aid): ?array
    {
        $this->dbs->query('SELECT secret, confirmed_at, last_step FROM `:prefix_admin_totp` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $row = $this->dbs->single();
        if (!is_array($row)) {
            return null;
        }
        return [
            'secret'       => (string) $row['secret'],
            'confirmed_at' => $row['confirmed_at'] === null ? null : (int) $row['confirmed_at'],
            'last_step'    => (int) $row['last_step'],
        ];
    }
}
