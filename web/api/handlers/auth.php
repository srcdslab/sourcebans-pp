<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

use Sbpp\Mail\EmailType;
use Sbpp\Mail\Mail;

/**
 * bcrypt hash of a random throwaway value, at the cost
 * `password_hash(PASSWORD_BCRYPT)` uses on PHP 8.4+ (12). Verifying
 * against it gives unknown usernames the same delay as real ones (#59).
 */
const API_AUTH_TIMING_DUMMY_HASH = '$2y$12$gaS4ruZ8z1k15YBlZL8toev5T.l7Bs4RMkwPxh8aGwGyTCr/FMaiG';

/**
 * Lifetime of a password reset link, in seconds (#96). The mail template
 * (`pass_reset.html`) says "1 hour": keep them in sync.
 */
const API_AUTH_PASSWORD_RESET_TTL = 3600;

function _api_auth_get_user(string $username): ?array
{
    $GLOBALS['PDO']->query("SELECT aid, password, attempts, lockout_until FROM `:prefix_admins` WHERE user = :user");
    $GLOBALS['PDO']->bind(':user', $username);
    $row = $GLOBALS['PDO']->single();
    return $row ?: null;
}

function api_auth_login(array $params): array
{
    $username = (string)($params['username'] ?? '');
    $password = (string)($params['password'] ?? '');
    $rememberRaw = $params['remember'] ?? null;
    $remember    = $rememberRaw === true || $rememberRaw === 'true';
    $redirect = (string)($params['redirect'] ?? '');

    if (!Config::getBool('config.enablenormallogin')) {
        return Api::redirect('?p=login&m=failed');
    }

    $maxAttempts = 5;
    $lockoutTime = 10 * 60;

    // Checked before the user lookup so known and unknown usernames get
    // the same answer. Pre-#59 an empty password returned `empty_pwd` for
    // existing accounts and `failed` for the rest: a one-request oracle.
    if ($password === '') {
        return Api::redirect('?p=login&m=empty_pwd');
    }

    $now = time();

    // Per-address limit (#97), checked before the user lookup so known
    // and unknown usernames get the same answer. It counts this attempt
    // now and gives it back on success.
    $clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $throttle = new \Sbpp\Auth\LoginThrottle($GLOBALS['PDO']);
    $ipRetryAfter = $throttle->reserve($clientIp, $now);
    if ($ipRetryAfter !== null) {
        return Api::redirect('?p=login&m=locked&time=' . (int) ceil($ipRetryAfter / 60));
    }

    $user = _api_auth_get_user($username);
    if (!$user) {
        // Pay the same bcrypt cost a known account does, so response time
        // doesn't reveal whether the username exists (#59).
        password_verify($password, API_AUTH_TIMING_DUMMY_HASH);
        return Api::redirect('?p=login&m=failed');
    }

    // Reserve this attempt on the account before checking the password
    // (#97). The lockout check, the increment and setting the lock are one
    // statement: requests sent in parallel each take a slot, and once the
    // slot that reaches $maxAttempts is taken the rest see the lock and
    // never reach password_verify(). Pre-#97 the check and the increment
    // were separate statements around the bcrypt check, so every parallel
    // request passed the check and got a guess.
    //
    // `lockout_until` is assigned first so it reads the old `attempts`.
    // Times are PHP-side `Y-m-d H:i:s`, as everywhere `lockout_until` is
    // read. Keeps the pre-#97 rule: after a lock expires, `attempts` is
    // still >= $maxAttempts, so one more wrong password locks again.
    $GLOBALS['PDO']->query(
        "UPDATE `:prefix_admins`
            SET lockout_until = IF(attempts + 1 >= :max, :until, lockout_until),
                attempts = attempts + 1
          WHERE aid = :aid AND (lockout_until IS NULL OR lockout_until <= :now)"
    );
    $GLOBALS['PDO']->bindMultiple([
        ':max'   => $maxAttempts,
        ':until' => date('Y-m-d H:i:s', $now + $lockoutTime),
        ':aid'   => (int) $user['aid'],
        ':now'   => date('Y-m-d H:i:s', $now),
    ]);
    $GLOBALS['PDO']->execute();
    if ($GLOBALS['PDO']->rowCount() === 0) {
        // Locked, by an earlier request or a concurrent one.
        return _api_auth_locked_redirect((int) $user['aid'], $now, $lockoutTime);
    }

    $auth = new NormalAuthHandler($GLOBALS['PDO'], $username, $password, $remember);

    if (!$auth->getResult()) {
        // The reservation above already counted the failure, and set the
        // lock if this was the last allowed attempt.
        $after = _api_auth_get_user($username);
        if (!empty($after['lockout_until']) && strtotime((string) $after['lockout_until']) > $now) {
            return _api_auth_locked_redirect((int) $user['aid'], $now, $lockoutTime);
        }
        return Api::redirect('?p=login&m=failed');
    }

    $GLOBALS['PDO']->query("UPDATE `:prefix_admins` SET attempts = 0, lockout_until = NULL WHERE aid = :aid");
    $GLOBALS['PDO']->bind(':aid', (int) $user['aid']);
    $GLOBALS['PDO']->execute();
    $throttle->release($clientIp);

    return Api::redirect('?' . $redirect);
}

/**
 * `?p=login&m=locked&time=<minutes left>` for a locked account.
 */
function _api_auth_locked_redirect(int $aid, int $now, int $lockoutTime): array
{
    $GLOBALS['PDO']->query("SELECT lockout_until FROM `:prefix_admins` WHERE aid = :aid");
    $GLOBALS['PDO']->bind(':aid', $aid);
    $row = $GLOBALS['PDO']->single();
    $until = is_array($row) && !empty($row['lockout_until']) ? strtotime((string) $row['lockout_until']) : false;
    $remaining = $until !== false && $until > $now ? $until - $now : $lockoutTime;
    return Api::redirect('?p=login&m=locked&time=' . round($remaining / 60));
}

/**
 * Generic response the lost-password handler returns for every reachable
 * branch — registered email, unregistered email, mail-send failure.
 *
 * Single source of truth so a future tweak (#1456 follow-up: copy
 * editing, locale support, etc.) doesn't have to be made in three
 * places and silently desync the wire shape one branch uses from the
 * other — which is exactly how the user-enumeration leak slips back in.
 *
 * The body intentionally uses "If an account is registered to that
 * email address…" rather than "We sent an email to…" so the message
 * is honest in both the matched and unmatched cases. Mirrors
 * Django's password_reset, Rails's devise/recoverable, and GitHub's
 * password-recovery defaults: indistinguishable response for present
 * vs absent accounts is the OWASP-aligned shape (OWASP ASVS v4
 * Credential Recovery §V2.5; OWASP Forgot Password Cheat Sheet §
 * "Return a consistent message"). The wording avoids "admin account
 * on this panel" — the panel URL + form heading already advertise
 * the surface, but the response copy itself should not narrow the
 * scope further (matches the major-framework convention).
 *
 * @return array{message: array{title: string, body: string, kind: string}}
 */
function _api_auth_lost_password_generic_response(): array
{
    return [
        'message' => [
            'title' => 'Check E-Mail',
            'body'  => 'If an account is registered to that email address, '
                . 'a password reset link has been sent. '
                . 'Please check your inbox (and your spam folder).',
            'kind'  => 'blue',
        ],
    ];
}

/**
 * Public password-recovery entrypoint.
 *
 * #1456 — DO NOT reveal whether the supplied email matches a row. The
 * pre-fix shape threw `ApiError('not_registered', …)` on the miss
 * branch, which let an unauthenticated visitor probe the panel for
 * registered email addresses one HTTP request at a time. The
 * post-fix contract:
 *
 *   - Unknown email          -> generic 'Check E-Mail' envelope.
 *   - Known email + send ok  -> generic 'Check E-Mail' envelope.
 *   - Known email + send err -> generic 'Check E-Mail' envelope,
 *                               server-side audit log entry only.
 *   - `config.enablenormallogin` off -> `disabled` error envelope
 *                               (an operator-side toggle, not a
 *                               per-user signal; revealing it does
 *                               not help an attacker enumerate).
 *
 * Audit-log semantics:
 *
 *   - Unknown email: NOT logged. Logging every miss would let an
 *     attacker flood `:prefix_log` with arbitrary garbage and double
 *     as a denial-of-service against the panel's log surface.
 *   - Known email + send ok: not logged at the handler level. The
 *     follow-up reset (`page.lostpassword.php`'s `?validation=…`
 *     branch) logs the actual password change.
 *   - Known email + send err: LogType::Error so an operator can
 *     diagnose the SMTP misconfiguration that's silently swallowing
 *     reset requests (otherwise the failure would be invisible).
 *
 * Caveat (documented in `AGENTS.md` "Public auth surfaces …"):
 * the response-shape uniformity above is the load-bearing privacy
 * gate, but the response-time differential remains — the matched
 * branch performs an SMTP round-trip, the missed branch does not.
 * A determined attacker can still enumerate via timing. Closing
 * that requires either a queued / asynchronous send (out of scope
 * here — the panel has no background worker), or a deliberate
 * pad-the-miss approach that's brittle in practice. Leaving the
 * timing leak open is the documented trade-off; the user-visible
 * envelope-shape leak (which the #1456 reporter saw) is closed.
 */
function api_auth_lost_password(array $params): array
{
    if (!Config::getBool('config.enablenormallogin')) {
        // `disabled` is an operator configuration, not a per-user
        // signal — same value returned for every caller — so the
        // error envelope is intentional here and does NOT enable
        // enumeration. The matching page-handler guard in
        // `page.lostpassword.php` 302s the form away on the same
        // toggle, so curl-driven callers are the only ones that
        // reach this branch.
        throw new ApiError('disabled', 'Normal login is disabled.');
    }

    $email = (string)($params['email'] ?? '');

    // `email` uses the table's case- and accent-insensitive collation, so
    // the request value can differ from the stored address. Everything
    // past the lookup keys on the stored row (`aid`, `email`), never on
    // the request string.
    $GLOBALS['PDO']->query("SELECT aid, user, email FROM `:prefix_admins` WHERE email = :email");
    $GLOBALS['PDO']->bind(':email', $email);
    $row = $GLOBALS['PDO']->single();

    // #1456: do NOT branch the response envelope on whether the email
    // matched. Every reachable branch below returns the same
    // _api_auth_lost_password_generic_response() shape, so a hostile
    // caller can't distinguish "this address has an admin account" from
    // "this address does not". The DB writes + SMTP round-trip only
    // run when the row exists — never send an email to an address
    // that did NOT request a reset, since that would turn the form
    // into an open mail relay / spam vector.
    if (empty($row['aid'])) {
        return _api_auth_lost_password_generic_response();
    }

    $storedEmail = (string) $row['email'];
    $validation  = Crypto::recoveryHash();
    // The deadline is a PHP-side `Y-m-d H:i:s`, like `lockout_until`, so it
    // compares in the same timezone `page.lostpassword.php` reads it in.
    $GLOBALS['PDO']->query("UPDATE `:prefix_admins` SET validate = :validate, validate_until = :until WHERE aid = :aid");
    $GLOBALS['PDO']->bind(':validate', $validation);
    $GLOBALS['PDO']->bind(':until', date('Y-m-d H:i:s', time() + API_AUTH_PASSWORD_RESET_TTL));
    $GLOBALS['PDO']->bind(':aid', (int) $row['aid']);
    $GLOBALS['PDO']->execute();

    $url = Host::panelUrl() . '/index.php?p=lostpassword&email=' . urlencode($storedEmail)
        . '&validation=' . urlencode($validation);

    $sent = Mail::send($storedEmail, EmailType::PasswordReset, [
        '{link}' => $url,
        '{name}' => $row['user'],
        '{home}' => Host::panelUrl(),
    ]);

    if (!$sent) {
        // Log the failure server-side so an operator can fix the SMTP
        // configuration (`Mail::send` already logs the underlying
        // `Mailer::create()` / transport exception via its own
        // `Log::add(LogType::Error, …)` calls, but those don't pin
        // the action that triggered them). Returning the generic
        // envelope means a legitimate user whose reset email failed
        // to send will be told to "check spam" and never receive
        // anything — operationally noisy, but the alternative is
        // surfacing `mail_failed` which would let an attacker
        // distinguish a registered email from an unregistered one
        // simply by toggling whether SMTP is configured (or by
        // submitting many requests; transient SMTP failures are
        // common).
        Log::add(
            LogType::Error,
            'Password reset mail failed',
            'Mail::send returned false while sending the password-reset link for an admin account.'
            . ' Check earlier "Mail not configured" / "Mail error" entries for the underlying cause.'
            . ' The user was shown the standard "check your email" confirmation; no email was sent.'
        );
        return _api_auth_lost_password_generic_response();
    }

    return _api_auth_lost_password_generic_response();
}
