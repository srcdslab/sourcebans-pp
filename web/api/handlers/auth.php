<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

use Sbpp\Auth\DeviceCookie;
use Sbpp\Auth\LoginThrottle;
use Sbpp\Auth\ThrottleHit;
use Sbpp\Auth\ThrottleUnavailable;
use Sbpp\Auth\TwoFactor;
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
    $GLOBALS['PDO']->query("SELECT aid, user, password FROM `:prefix_admins` WHERE user = :user");
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

    // Checked before the user lookup so known and unknown usernames get
    // the same answer. Pre-#59 an empty password returned `empty_pwd` for
    // existing accounts and `failed` for the rest: a one-request oracle.
    if ($password === '') {
        return Api::redirect('?p=login&m=empty_pwd');
    }

    $now = time();
    $clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $throttle = new LoginThrottle($GLOBALS['PDO']);
    $ipKey = LoginThrottle::addressKey($clientIp);
    $ipCounter = $ipKey !== null && LoginThrottle::ipLimit() > 0 ? 'ip:' . $ipKey : null;

    // Every counter takes its slot before the password is checked (#97)
    // and gives it back on success. A missing table refuses the sign-in
    // (#106): pre-#106 it let every attempt through uncounted.
    try {
        // Per address, before the user lookup: the same answer for known
        // and unknown usernames.
        if ($ipCounter !== null) {
            $ipHit = $throttle->hit($ipCounter, LoginThrottle::ipLimit(), LoginThrottle::WINDOW_SECONDS, $now);
            if ($ipHit->blocked()) {
                if ($ipHit->trippedNow()) {
                    _api_auth_log_address_throttled($clientIp, $ipHit);
                }
                return _api_auth_locked_redirect($ipHit->retryAfter);
            }
        }

        // Per username (#106). The key is the name as the `user` column
        // compares it, so case or accent variants share one counter, and
        // unknown names are counted like real ones. A browser holding a
        // device cookie for this name is charged on its own counter, so
        // filling the shared one can't lock the real admin out.
        $user = _api_auth_get_user($username);
        $nameKey = $throttle->nameKey($user !== null ? (string) $user['user'] : $username, $user !== null);
        $deviceNonce = DeviceCookie::nonceFor($nameKey, $now);
        $counter = $deviceNonce !== null ? DeviceCookie::counterKey($deviceNonce) : 'n:' . $nameKey;
        $hit = $throttle->hit($counter, LoginThrottle::ACCOUNT_LIMIT, LoginThrottle::WINDOW_SECONDS, $now);
    } catch (ThrottleUnavailable $e) {
        error_log('[sbpp] password sign-in refused, the sign-in counters are unavailable (run the updater): ' . $e->getMessage());
        return Api::redirect('?p=login&m=unavailable');
    }

    if ($hit->blocked()) {
        // No password check: known and unknown names both answer at once.
        if ($hit->trippedNow() && $user !== null) {
            _api_auth_log_account_throttled((string) $user['user'], $deviceNonce !== null);
        }
        return _api_auth_locked_redirect($hit->retryAfter);
    }

    if ($user === null) {
        // Pay the same bcrypt cost a known account does, so response time
        // doesn't reveal whether the username exists (#59).
        password_verify($password, API_AUTH_TIMING_DUMMY_HASH);
        return Api::redirect('?p=login&m=failed');
    }

    $auth = new NormalAuthHandler($GLOBALS['PDO'], $username, $password, $remember);

    if (!$auth->getResult()) {
        // The hits above already counted the failure.
        return Api::redirect('?p=login&m=failed');
    }

    $throttle->release($counter);
    if ($ipCounter !== null) {
        $throttle->release($ipCounter);
    }
    DeviceCookie::issue($nameKey, $now);

    // Starts the session, or the second step for an admin with 2FA (or
    // one the `auth.2fa.require` setting covers who must set it up, #107).
    try {
        return Api::redirect((new TwoFactor($GLOBALS['PDO']))->completePrimary($auth->aid(), $auth->maxlife(), $redirect));
    } catch (\PDOException $e) {
        // Can't tell whether this admin has 2FA: refuse rather than skip it.
        error_log('[sbpp] password sign-in refused, two-factor state unreadable (run the updater): ' . $e->getMessage());
        return Api::redirect('?p=login&m=unavailable');
    }
}

// ---- Second step (#107) ---------------------------------------------------
//
// Public actions: the browser has no session yet, only the `sbpp_2fa`
// pending cookie set by TwoFactor::completePrimary(). Every answer that
// isn't a success is about that pending step, never about the account.

/** Map a failed TwoFactor result to the wire. */
function _api_auth_2fa_failure(array $res): array
{
    return match ($res['error'] ?? '') {
        'invalid'     => throw new ApiError('invalid_code', "That code isn't valid. Check the time on your phone, or use a recovery code.", 'code'),
        'locked'      => throw new ApiError(
            'locked',
            'Too many wrong codes. Try again in about ' . max(1, (int) ceil(((int) ($res['retry_after'] ?? 60)) / 60)) . ' minutes.',
            'code',
        ),
        'unavailable' => Api::redirect('?p=login&m=unavailable'),
        default       => Api::redirect('?p=login&m=2fa_expired'),
    };
}

function api_auth_2fa_verify(array $params): array
{
    $res = (new TwoFactor($GLOBALS['PDO']))->verifyPending((string) ($params['code'] ?? ''), time());
    if ($res['ok'] !== true) {
        return _api_auth_2fa_failure($res);
    }
    return Api::redirect($res['redirect']);
}

function api_auth_2fa_enroll_start(array $params): array
{
    $tf = new TwoFactor($GLOBALS['PDO']);
    $pending = $tf->pending();
    if ($pending === null || $pending['purpose'] !== TwoFactor::PURPOSE_ENROLL) {
        return Api::redirect('?p=login&m=2fa_expired');
    }
    $GLOBALS['PDO']->query('SELECT user FROM `:prefix_admins` WHERE aid = :aid');
    $GLOBALS['PDO']->bind(':aid', $pending['aid']);
    $row = $GLOBALS['PDO']->single();
    $setup = is_array($row) ? $tf->beginSetup($pending['aid'], (string) $row['user']) : null;
    if ($setup === null) {
        $tf->closePending();
        return Api::redirect('?p=login&m=2fa_expired');
    }
    return [
        'secret' => $setup['secret'],
        'uri'    => $setup['uri'],
        'qr'     => \Sbpp\Security\QrCode::svgDataUri($setup['uri']),
    ];
}

function api_auth_2fa_enroll_confirm(array $params): array
{
    $res = (new TwoFactor($GLOBALS['PDO']))->confirmPendingEnrolment((string) ($params['code'] ?? ''), time());
    if ($res['ok'] !== true) {
        return _api_auth_2fa_failure($res);
    }
    // Not a redirect: the page shows the recovery codes first.
    return ['recovery_codes' => $res['recovery_codes'], 'next' => $res['redirect']];
}

// ---- Passkeys (#108) ------------------------------------------------------

/**
 * Passwordless sign-in, step 1: options for any discoverable passkey of
 * this panel. Public; the same answer for everyone.
 */
function api_auth_passkey_login_start(array $params): array
{
    if (!\Sbpp\Auth\Passkeys::available()) {
        throw new ApiError('unavailable', 'Passkeys are not set up on this panel.');
    }
    return ['options' => (new \Sbpp\Auth\Passkeys($GLOBALS['PDO']))->requestOptions(\Sbpp\Auth\Passkeys::PURPOSE_LOGIN, null)];
}

/**
 * Passwordless sign-in, step 2. A passkey with user verification is two
 * factors on its own: the session starts, `auth.2fa.require` is met.
 * Failures are counted on the address counter like passwords, and all
 * answer the same.
 */
function api_auth_passkey_login_finish(array $params): array
{
    if (!\Sbpp\Auth\Passkeys::available()) {
        throw new ApiError('unavailable', 'Passkeys are not set up on this panel.');
    }
    $now = time();
    $throttle = new LoginThrottle($GLOBALS['PDO']);
    $ipKey = LoginThrottle::addressKey((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    $ipCounter = $ipKey !== null && LoginThrottle::ipLimit() > 0 ? 'ip:' . $ipKey : null;
    try {
        if ($ipCounter !== null) {
            $hit = $throttle->hit($ipCounter, LoginThrottle::ipLimit(), LoginThrottle::WINDOW_SECONDS, $now);
            if ($hit->blocked()) {
                return _api_auth_locked_redirect($hit->retryAfter);
            }
        }
    } catch (ThrottleUnavailable $e) {
        error_log('[sbpp] passkey sign-in refused, the sign-in counters are unavailable (run the updater): ' . $e->getMessage());
        return Api::redirect('?p=login&m=unavailable');
    }

    $credential = $params['credential'] ?? null;
    $aid = is_array($credential)
        ? (new \Sbpp\Auth\Passkeys($GLOBALS['PDO']))->finishAssertion(\Sbpp\Auth\Passkeys::PURPOSE_LOGIN, $credential, null, $now)
        : null;
    if ($aid === null || !_api_auth_admin_enabled($aid)) {
        return Api::redirect('?p=login&m=passkey_failed');
    }

    if ($ipCounter !== null) {
        $throttle->release($ipCounter);
    }
    (new TwoFactor($GLOBALS['PDO']))->completeStrong($aid, (int) Config::get('auth.maxlife') * 60);
    return Api::redirect('?' . (string) ($params['redirect'] ?? ''));
}

/** Soft-retired admins (`enabled = 0`) can't sign in with a passkey either. */
function _api_auth_admin_enabled(int $aid): bool
{
    $enabled = \Sbpp\Auth\AdminsSchema::hasEnabledColumn($GLOBALS['PDO']) ? ', enabled' : '';
    $GLOBALS['PDO']->query("SELECT aid{$enabled} FROM `:prefix_admins` WHERE aid = :aid");
    $GLOBALS['PDO']->bind(':aid', $aid);
    $row = $GLOBALS['PDO']->single();
    return is_array($row) && (int) ($row['enabled'] ?? 1) === 1;
}

/** Second step with a passkey: options for the pending admin's passkeys. */
function api_auth_2fa_passkey_start(array $params): array
{
    $options = (new TwoFactor($GLOBALS['PDO']))->pendingPasskeyOptions();
    if ($options === null) {
        return Api::redirect('?p=login&m=2fa_expired');
    }
    return ['options' => $options];
}

function api_auth_2fa_passkey_finish(array $params): array
{
    $credential = $params['credential'] ?? null;
    $res = (new TwoFactor($GLOBALS['PDO']))->verifyPendingWithPasskey(is_array($credential) ? $credential : [], time());
    if ($res['ok'] !== true) {
        if ($res['error'] === 'invalid_passkey') {
            throw new ApiError('invalid_passkey', "That passkey couldn't be verified. Try again, or use a code.");
        }
        return _api_auth_2fa_failure($res);
    }
    return Api::redirect($res['redirect']);
}

function api_auth_2fa_cancel(array $params): array
{
    (new TwoFactor($GLOBALS['PDO']))->closePending();
    return Api::redirect('?p=login');
}

/** `?p=login&m=locked&time=<minutes left>`, the same for every counter. */
function _api_auth_locked_redirect(int $retryAfter): array
{
    return Api::redirect('?p=login&m=locked&time=' . max(1, (int) ceil($retryAfter / 60)));
}

/**
 * One audit entry when an address reaches its limit (#106): the first
 * refused attempt of the window, so a flood writes one row, not one per
 * request. The `host` column records the address.
 */
function _api_auth_log_address_throttled(string $ip, ThrottleHit $hit): void
{
    $message = sprintf(
        '%d failed password sign-ins from this address in %d minutes. Password sign-in from it is refused for %d more minutes.',
        $hit->limit,
        intdiv(LoginThrottle::WINDOW_SECONDS, 60),
        max(1, (int) ceil($hit->retryAfter / 60)),
    );
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        // A private address is usually the reverse proxy: then every
        // visitor shares its counter.
        $message .= ' This is a private address: if it is your reverse proxy, the panel does not see client'
            . ' addresses and every visitor shares this limit (set SBPP_TRUSTED_PROXIES, or your web server\'s'
            . ' real-IP module).';
    }
    Log::add(LogType::Warning, 'Sign-in throttled', $message);
}

/** One audit entry when an existing account's counter reaches its limit (#106). */
function _api_auth_log_account_throttled(string $user, bool $trustedDevice): void
{
    $minutes = intdiv(LoginThrottle::WINDOW_SECONDS, 60);
    $message = $trustedDevice
        ? sprintf(
            '%d failed password sign-ins for admin "%s" in %d minutes from a browser that signed in as this admin before.'
            . ' That browser is refused for up to %d minutes; other browsers are not affected.',
            LoginThrottle::ACCOUNT_LIMIT, $user, $minutes, $minutes,
        )
        : sprintf(
            '%d failed password sign-ins for admin "%s" in %d minutes from browsers that never signed in as this admin.'
            . ' Those browsers are refused for up to %d minutes. Browsers that signed in as this admin before,'
            . ' and Steam sign-in, still work.',
            LoginThrottle::ACCOUNT_LIMIT, $user, $minutes, $minutes,
        );
    Log::add(LogType::Warning, 'Sign-in locked', $message);
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

    // #106: reset requests are limited per address (before the lookup, so
    // known and unknown emails answer the same) and per account (so a
    // known address can't be mailed over and over, which also rolled the
    // owner's pending reset link on every request). Over a limit, or with
    // the counters unavailable, the request gets the generic answer and
    // nothing is sent.
    $now = time();
    $throttle = new LoginThrottle($GLOBALS['PDO']);
    $ipKey = LoginThrottle::addressKey((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    try {
        // SBPP_LOGIN_IP_LIMIT=0 means the panel can't see client
        // addresses: don't limit per address here either.
        if ($ipKey !== null && LoginThrottle::ipLimit() > 0) {
            $ipHit = $throttle->hit(
                'lpi:' . $ipKey,
                LoginThrottle::RESET_IP_LIMIT,
                LoginThrottle::RESET_WINDOW_SECONDS,
                $now,
            );
            if ($ipHit->blocked()) {
                return _api_auth_lost_password_generic_response();
            }
        }
    } catch (ThrottleUnavailable $e) {
        error_log('[sbpp] password reset refused, the sign-in counters are unavailable (run the updater): ' . $e->getMessage());
        return _api_auth_lost_password_generic_response();
    }

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

    try {
        $accountHit = $throttle->hit(
            'lpa:' . (int) $row['aid'],
            LoginThrottle::RESET_ACCOUNT_LIMIT,
            LoginThrottle::RESET_WINDOW_SECONDS,
            $now,
        );
    } catch (ThrottleUnavailable $e) {
        error_log('[sbpp] password reset refused, the sign-in counters are unavailable (run the updater): ' . $e->getMessage());
        return _api_auth_lost_password_generic_response();
    }
    if ($accountHit->blocked()) {
        if ($accountHit->trippedNow()) {
            Log::add(
                LogType::Warning,
                'Password reset throttled',
                sprintf(
                    '%d password reset requests for admin "%s" in %d minutes. Further requests send no mail for up to %d minutes;'
                    . ' the last reset link sent stays valid.',
                    LoginThrottle::RESET_ACCOUNT_LIMIT,
                    (string) $row['user'],
                    intdiv(LoginThrottle::RESET_WINDOW_SECONDS, 60),
                    max(1, (int) ceil($accountHit->retryAfter / 60)),
                ),
            );
        }
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
