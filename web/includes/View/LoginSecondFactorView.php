<?php

declare(strict_types=1);

namespace Sbpp\View;

/**
 * Second sign-in step (#107), rendered by `page.login.php` for
 * `?p=login&step=2fa` (enter a code) and `?p=login&step=enroll` (the
 * `auth.2fa.require` setting covers this admin: set 2FA up first). The
 * browser has no session yet, only the `sbpp_2fa` pending cookie; the page
 * talks to the `auth.2fa_*` actions.
 *
 * Same `-{ … }-` delimiters as {@see LoginView}, so the inline script can
 * use `{` / `}`.
 */
final class LoginSecondFactorView extends View
{
    public const TEMPLATE = 'page_login_2fa.tpl';

    /** @var array{0: '-{', 1: '}-'} */
    public const DELIMITERS = ['-{', '}-'];

    public function __construct(
        /** `verify` or `enroll` ({@see \Sbpp\Auth\TwoFactor::PURPOSE_VERIFY}). */
        public readonly string $mode,
        public readonly string $brand_logo_url,
    ) {
    }

    public static function breadcrumb(): array
    {
        return [
            ['title' => 'Sign in', 'url' => 'index.php?p=login'],
        ];
    }
}
