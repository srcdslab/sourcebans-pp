-{*
    Second sign-in step (#107). View: Sbpp\View\LoginSecondFactorView.
    `-{ … }-` delimiters like page_login.tpl, so the script below can use
    `{` / `}`.

    $mode = 'verify': the admin has 2FA; send a TOTP or recovery code to
        Actions.Auth2faVerify (redirect envelope on success).
    $mode = 'enroll': `auth.2fa.require` covers the admin and 2FA is off;
        Actions.Auth2faEnrollStart returns the secret + QR code (a data:
        URI shown in an <img>, never inlined as markup), then
        Actions.Auth2faEnrollConfirm returns the recovery codes, shown once
        before going on.

    Testability hooks:
      data-testid="login-2fa-form"        — code form
      data-testid="login-2fa-code"        — code input
      data-testid="login-2fa-submit"      — submit button
      data-testid="login-2fa-error"       — inline error line
      data-testid="login-2fa-cancel"      — cancel link
      data-testid="login-2fa-qr"          — QR code <img> (enroll)
      data-testid="login-2fa-secret"      — secret as text (enroll)
      data-testid="login-2fa-recovery"    — recovery codes block (enroll)
      data-testid="login-2fa-continue"    — "continue" button after the codes
*}-
<div class="login-shell">
    <div class="card login-shell__card">
        <div class="card__body">
            <div class="flex items-center gap-3 mb-6">
                <img class="sidebar__brand-mark" data-testid="brand-mark" src="-{$brand_logo_url}-" alt="" aria-hidden="true">
                <div>
                    <div class="font-semibold text-sm">SourceBans++</div>
                    <div class="text-xs text-muted">Admin panel</div>
                </div>
            </div>

            -{if $mode == 'enroll'}-
                <h1 class="m-0" style="font-size:var(--fs-2xl);font-weight:600">Set up two-factor authentication</h1>
                <p class="text-sm text-muted mt-2">
                    This panel requires two-factor authentication for your account.
                    Scan the QR code with an authenticator app (Aegis, 2FAS, Google Authenticator, 1Password…),
                    then enter the 6-digit code it shows.
                </p>
                <div id="twofaSetup" class="mt-4" style="text-align:center">
                    <img id="twofaQr" data-testid="login-2fa-qr" alt="QR code for your authenticator app" width="200" height="200" style="background:#fff;padding:.5rem;border-radius:var(--radius-md);display:none;margin:0 auto">
                    <p class="text-xs text-muted mt-2">Can't scan it? Enter this key:</p>
                    <code id="twofaSecret" data-testid="login-2fa-secret" style="word-break:break-all"></code>
                </div>
            -{else}-
                <h1 class="m-0" style="font-size:var(--fs-2xl);font-weight:600">Two-factor authentication</h1>
                <p class="text-sm text-muted mt-2">
                    -{if $code_show}-Enter the 6-digit code from your authenticator app, or one of your recovery codes.-{/if}-
                    -{if $passkey_show}- Or confirm with one of your passkeys.-{/if}-
                </p>
                -{if $passkey_show}-
                    <button type="button" class="btn btn--secondary mt-4" id="twofaPasskey" data-testid="login-2fa-passkey" hidden style="width:100%">
                        <i data-lucide="key-round" aria-hidden="true"></i> Use a passkey
                    </button>
                -{/if}-
            -{/if}-

            <form id="twofaForm" class="space-y-3 mt-4" data-testid="login-2fa-form" data-mode="-{$mode}-" novalidate autocomplete="off"-{if !$code_show}- hidden-{/if}->
                -{csrf_field}-
                <div>
                    <label class="label" for="twofaCode">Code</label>
                    <input class="input"
                           id="twofaCode"
                           name="code"
                           type="text"
                           inputmode="-{if $mode == 'enroll'}-numeric-{else}-text-{/if}-"
                           autocomplete="one-time-code"
                           autocapitalize="characters"
                           spellcheck="false"
                           maxlength="24"
                           required
                           autofocus
                           data-testid="login-2fa-code">
                </div>
                <p id="twofaError" class="text-xs" role="alert" data-testid="login-2fa-error" style="color:var(--danger);min-height:1em"></p>
                <button class="btn btn--primary" type="submit" data-testid="login-2fa-submit" style="width:100%">
                    -{if $mode == 'enroll'}-Turn on and sign in-{else}-Verify-{/if}- <i data-lucide="arrow-right" aria-hidden="true"></i>
                </button>
            </form>

            <div id="twofaRecovery" data-testid="login-2fa-recovery" class="mt-4" hidden>
                <p class="text-sm"><strong>Save your recovery codes.</strong> Each one signs you in once if you lose your phone. They are shown only now.</p>
                <pre id="twofaRecoveryList" class="mt-2" style="font-size:var(--fs-sm);line-height:1.6;user-select:all"></pre>
                <button id="twofaContinue" class="btn btn--primary" type="button" data-testid="login-2fa-continue" style="width:100%">
                    I saved them, continue <i data-lucide="arrow-right" aria-hidden="true"></i>
                </button>
            </div>

            <div class="mt-4 text-xs" style="text-align:center">
                <a href="index.php?p=login" id="twofaCancel" data-testid="login-2fa-cancel">Cancel and sign in again</a>
            </div>
        </div>
    </div>
</div>

<style>
    .login-shell { display:flex; justify-content:center; padding:2.5rem 1rem; }
    .login-shell__card { width:100%; max-width:24rem; }
</style>

<script>
(function () {
    'use strict';

    function setBusy(btn, busy) {
        if (!btn) return;
        var S = window.SBPP;
        if (S && typeof S.setBusy === 'function') S.setBusy(btn, busy);
        else btn.disabled = busy === undefined ? true : !!busy;
    }

    var form = document.getElementById('twofaForm');
    if (!form) return;
    var mode = form.getAttribute('data-mode');
    var input = document.getElementById('twofaCode');
    var errorLine = document.getElementById('twofaError');
    var submitBtn = form.querySelector('[data-testid="login-2fa-submit"]');

    function showError(res) {
        var msg = (res && res.error && res.error.message) || 'Something went wrong. Try again.';
        errorLine.textContent = msg;
        setBusy(submitBtn, false);
        if (input) { input.value = ''; input.focus(); }
    }

    if (mode === 'enroll') {
        sb.api.call(Actions.Auth2faEnrollStart, {}).then(function (res) {
            if (!res || res.ok !== true || !res.data) {
                if (!res || !res.redirect) showError(res);
                return;
            }
            var qr = document.getElementById('twofaQr');
            // A data: URI in an <img>: the SVG is never parsed as page markup.
            if (qr && typeof res.data.qr === 'string' && res.data.qr.indexOf('data:image/svg+xml;base64,') === 0) {
                qr.src = res.data.qr;
                qr.style.display = 'block';
            }
            var secret = document.getElementById('twofaSecret');
            if (secret) secret.textContent = String(res.data.secret || '').replace(/(.{4})/g, '$1 ').trim();
        });
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        errorLine.textContent = '';
        setBusy(submitBtn, true);
        var action = mode === 'enroll' ? Actions.Auth2faEnrollConfirm : Actions.Auth2faVerify;
        sb.api.call(action, { code: input ? input.value : '' }).then(function (res) {
            if (res && res.redirect) return; // api.js navigates.
            if (!res || res.ok !== true) { showError(res); return; }
            if (mode === 'enroll' && res.data && Array.isArray(res.data.recovery_codes)) {
                form.hidden = true;
                var setup = document.getElementById('twofaSetup');
                if (setup) setup.hidden = true;
                document.getElementById('twofaRecoveryList').textContent = res.data.recovery_codes.join('\n');
                document.getElementById('twofaRecovery').hidden = false;
                var next = typeof res.data.next === 'string' && res.data.next.charAt(0) === '?' ? res.data.next : '?';
                document.getElementById('twofaContinue').addEventListener('click', function () {
                    window.location.href = 'index.php' + next;
                });
            }
        }, function () { showError(null); });
    });

    // Passkey as the second step (#108).
    var pkBtn = document.getElementById('twofaPasskey');
    var PK = window.SBPP_PASSKEYS;
    if (pkBtn && PK && PK.supported()) {
        pkBtn.hidden = false;
        pkBtn.addEventListener('click', function () {
            errorLine.textContent = '';
            setBusy(pkBtn, true);
            sb.api.call(Actions.Auth2faPasskeyStart, {}).then(function (res) {
                if (!res || res.ok !== true || !res.data) { setBusy(pkBtn, false); return null; }
                return PK.get(res.data.options).then(function (credential) {
                    return sb.api.call(Actions.Auth2faPasskeyFinish, { credential: credential });
                }).then(function (r) {
                    if (r && r.redirect) return;
                    setBusy(pkBtn, false);
                    errorLine.textContent = (r && r.error && r.error.message) || 'Something went wrong. Try again.';
                });
            }).catch(function () { setBusy(pkBtn, false); });
        });
    }

    var cancel = document.getElementById('twofaCancel');
    if (cancel) {
        cancel.addEventListener('click', function (e) {
            e.preventDefault();
            sb.api.call(Actions.Auth2faCancel, {});
        });
    }
}());
</script>
