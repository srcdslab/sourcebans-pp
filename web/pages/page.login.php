<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

if (!defined("IN_SB")) {
    echo "You should not be here. Only follow links!";
    die();
}

global $userbank, $theme;

if ($userbank->is_logged_in()) {
    echo "<script>window.location.href = 'index.php';</script>";
    exit;
}

// `?m=…` query params drive a status banner. The shipped
// `page_login.tpl` renders the message via `window.SBPP.showToast()`
// off the URL params on page load, so this handler emits no
// server-rendered text. The pre-v2.0.0 inline `ShowBox()` blocks were
// removed (security audit 2026-11): they interpolated
// `Host::complete()` (built from the request path) into a JS string
// literal unescaped, a reflected XSS on the login form.

// `$redir` is a v1.x-shaped *JavaScript expression* preserved here for
// SmartyTemplateRule property↔reference parity (see the LoginView
// docblock). The shipped `page_login.tpl` echoes it on a dead
// `data-legacy-redir="…"` attribute and posts via
// `sb.api.call(Actions.AuthLogin, …)` with a hardcoded `redirect: ''`
// (post-login destination is the dashboard). Any third-party theme
// that forked the pre-v2.0.0 default and still calls `DoLogin(...)`
// from removed legacy bulk JS would no-op there.
// `template.logo` is the operator-configurable brand mark path. The
// `BrandLogo::resolveUrl()` helper handles the theme-relative join
// AND falls back to `images/favicon.svg` (the SourceBans++ shield
// from the favicon set) when the configured value is empty, points
// at the v1.x default `logos/sb-large.png` (which the v2.0 default
// theme never shipped), or points at a file that's been deleted
// from disk. Pre-fix this handler concatenated the raw
// `Config::get('template.logo')` value into a URL with no
// existence check, so any of the three broken-input shapes
// rendered a broken `<img>` on the sign-in card; the fallback now
// matches what the sidebar mark does via `core/header.php`.
$brandLogoUrl = \Sbpp\View\BrandLogo::resolveUrl();

// Second sign-in step (#107): the password or Steam check passed and the
// browser holds a pending `sbpp_2fa` cookie. Without a live pending step
// of the matching kind, start over.
$step = is_string($_GET['step'] ?? null) ? $_GET['step'] : '';
if ($step === '2fa' || $step === 'enroll') {
    $wanted = $step === '2fa' ? \Sbpp\Auth\TwoFactor::PURPOSE_VERIFY : \Sbpp\Auth\TwoFactor::PURPOSE_ENROLL;
    try {
        $pending = (new \Sbpp\Auth\TwoFactor($GLOBALS['PDO']))->pending();
    } catch (\PDOException) {
        $pending = null;
    }
    if ($pending === null || $pending['purpose'] !== $wanted) {
        // JS redirect: the chrome is already flushed (see the logged-in
        // guard above).
        echo "<script>window.location.href = 'index.php?p=login&m=2fa_expired';</script>";
        exit;
    }
    $tf = new \Sbpp\Auth\TwoFactor($GLOBALS['PDO']);
    $isVerify = $wanted === \Sbpp\Auth\TwoFactor::PURPOSE_VERIFY;
    $secondFactorView = new \Sbpp\View\LoginSecondFactorView(
        mode: $wanted,
        brand_logo_url: $brandLogoUrl,
        passkey_show: $isVerify && \Sbpp\Auth\Passkeys::available()
            && (new \Sbpp\Auth\Passkeys($GLOBALS['PDO']))->count($pending['aid']) > 0,
        code_show: !$isVerify || $tf->isEnrolled($pending['aid']) || $tf->recoveryCodesLeft($pending['aid']) > 0,
    );
    $theme->setLeftDelimiter('-{');
    $theme->setRightDelimiter('}-');
    \Sbpp\View\Renderer::render($theme, $secondFactorView);
    $theme->setLeftDelimiter('{');
    $theme->setRightDelimiter('}');
    return;
}

$loginView = new \Sbpp\View\LoginView(
    normallogin_show: Config::getBool('config.enablenormallogin'),
    steamlogin_show: Config::getBool('config.enablesteamlogin'),
    redir: "DoLogin('');",
    brand_logo_url: $brandLogoUrl,
    passkey_login_show: \Sbpp\Auth\Passkeys::available(),
);

// `page_login.tpl` renders with the custom `-{ … }-` delimiter pair so
// inline `<script>` blocks can keep `{` / `}` for JS object literals
// without `{literal}` wrapping. Swap delimiters around
// `Renderer::render()` so the chrome (which uses the standard
// `{ … }` pair) is unaffected. {@see LoginView::DELIMITERS}.
$theme->setLeftDelimiter('-{');
$theme->setRightDelimiter('}-');
\Sbpp\View\Renderer::render($theme, $loginView);
$theme->setLeftDelimiter('{');
$theme->setRightDelimiter('}');
