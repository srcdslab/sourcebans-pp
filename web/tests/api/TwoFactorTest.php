<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Tests\Api;

use Sbpp\Auth\TwoFactor;
use Sbpp\Security\SecretBox;
use Sbpp\Security\Totp;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #107: two-factor authentication. Password and Steam sign-ins end in
 * TwoFactor::completePrimary(); an admin with 2FA gets a pending step, not
 * a session, until a code is accepted.
 */
final class TwoFactorTest extends ApiTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Fixture::reset() keeps sessions; this test counts them.
        Fixture::rawPdo()->exec('DELETE FROM `' . DB_PREFIX . '_login_tokens`');
    }

    protected function tearDown(): void
    {
        unset($_COOKIE[TwoFactor::PENDING_COOKIE]);
        parent::tearDown();
    }

    // -- Without 2FA ----------------------------------------------------

    public function testPasswordLoginWithout2faStartsTheSessionAsBefore(): void
    {
        $env = $this->login();

        $this->assertSame('?', $env['redirect'] ?? null);
        $this->assertSame(1, $this->sessions());
        $this->assertArrayNotHasKey(TwoFactor::PENDING_COOKIE, $_COOKIE);
    }

    // -- Setup from Your account ----------------------------------------

    public function testSetupNeedsTheCurrentPasswordAndAValidCode(): void
    {
        $this->loginAsAdmin();

        $bad = $this->api('account.2fa_setup_start', ['password' => 'wrong']);
        $this->assertSame('bad_password', $bad['error']['code'] ?? null);

        $start = $this->api('account.2fa_setup_start', ['password' => 'admin']);
        $this->assertTrue($start['ok'] ?? false, json_encode($start));
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{32}$/D', $start['data']['secret']);
        $this->assertStringStartsWith('otpauth://totp/', $start['data']['uri']);
        $this->assertStringStartsWith('data:image/svg+xml;base64,', $start['data']['qr']);
        $this->assertStringContainsString('<svg', (string) base64_decode(substr($start['data']['qr'], 26), true));
        $this->assertFalse($this->tf()->isEnrolled(Fixture::adminAid()), 'Not on until confirmed.');

        $wrong = $this->api('account.2fa_setup_confirm', ['code' => '000000']);
        $this->assertSame('invalid_code', $wrong['error']['code'] ?? null);

        $ok = $this->api('account.2fa_setup_confirm', ['code' => $this->codeFor($start['data']['secret'])]);
        $this->assertTrue($ok['ok'] ?? false, json_encode($ok));
        $this->assertCount(TwoFactor::RECOVERY_CODES, $ok['data']['recovery_codes']);
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/D', $ok['data']['recovery_codes'][0]);
        $this->assertTrue($this->tf()->isEnrolled(Fixture::adminAid()));
        $this->assertSame(1, $this->logCount('Two-factor enabled'));
    }

    public function testSecretIsStoredSealedNotInClear(): void
    {
        $secret = $this->enroll();

        $row = $this->row('admin_totp', ['aid' => Fixture::adminAid()]);
        $this->assertStringNotContainsString($secret, (string) $row['secret']);
        $this->assertSame($secret, SecretBox::open((string) $row['secret'], 'totp'));

        $codes = $this->rows('admin_recovery_codes', ['aid' => Fixture::adminAid()]);
        $this->assertCount(TwoFactor::RECOVERY_CODES, $codes);
        foreach ($codes as $c) {
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', (string) $c['code_hash'], 'Only hashes are stored.');
        }
    }

    // -- Sign-in with 2FA -----------------------------------------------

    public function testPasswordLoginWith2faGivesAPendingStepNotASession(): void
    {
        $secret = $this->enroll();

        $env = $this->login();

        $this->assertSame('?p=login&step=2fa', $env['redirect'] ?? null);
        $this->assertSame(0, $this->sessions(), 'No session before the code.');
        $this->assertArrayHasKey(TwoFactor::PENDING_COOKIE, $_COOKIE);

        $wrong = $this->api('auth.2fa_verify', ['code' => '000000']);
        $this->assertSame('invalid_code', $wrong['error']['code'] ?? null);
        $this->assertSame(0, $this->sessions());

        // Setup used the current step: the next one is still in the window.
        $ok = $this->api('auth.2fa_verify', ['code' => $this->codeFor($secret, 1)]);
        $this->assertSame('?', $ok['redirect'] ?? null);
        $this->assertSame(1, $this->sessions());
        $this->assertSame(0, (int) Fixture::rawPdo()->query('SELECT COUNT(*) FROM `' . DB_PREFIX . '_auth_pending`')->fetchColumn());
    }

    public function testACodeIsAcceptedOnce(): void
    {
        $secret = $this->enroll();
        $code = $this->codeFor($secret, 1);

        $this->login();
        $this->assertSame('?', $this->api('auth.2fa_verify', ['code' => $code])['redirect'] ?? null);

        $this->login();
        $replay = $this->api('auth.2fa_verify', ['code' => $code]);
        $this->assertSame('invalid_code', $replay['error']['code'] ?? null, 'Replaying a used code fails.');
    }

    public function testRecoveryCodeSignsInOnceAndIsLogged(): void
    {
        $this->enroll();
        $codes = $this->lastRecoveryCodes;

        $this->login();
        $ok = $this->api('auth.2fa_verify', ['code' => strtolower(str_replace('-', ' ', $codes[0]))]);
        $this->assertSame('?', $ok['redirect'] ?? null, 'Case, spaces and dashes are ignored.');
        $this->assertSame(TwoFactor::RECOVERY_CODES - 1, $this->tf()->recoveryCodesLeft(Fixture::adminAid()));
        $this->assertSame(1, $this->logCount('Two-factor recovery code used'));

        $this->login();
        $again = $this->api('auth.2fa_verify', ['code' => $codes[0]]);
        $this->assertSame('invalid_code', $again['error']['code'] ?? null);
    }

    public function testFiveWrongCodesEndThePendingStep(): void
    {
        $secret = $this->enroll();
        $this->login();
        for ($i = 0; $i < TwoFactor::PENDING_ATTEMPTS; $i++) {
            $this->api('auth.2fa_verify', ['code' => '000000']);
        }

        $env = $this->api('auth.2fa_verify', ['code' => $this->codeFor($secret)]);

        $this->assertSame('?p=login&m=2fa_expired', $env['redirect'] ?? null, 'Even the right code needs a new sign-in.');
        $this->assertSame(0, $this->sessions());
    }

    public function testWrongCodesAreCappedPerAccountAcrossPendingSteps(): void
    {
        $secret = $this->enroll();
        for ($round = 0; $round < 3; $round++) {
            $this->login();
            for ($i = 0; $i < 4; $i++) {
                $this->api('auth.2fa_verify', ['code' => '000000']);
            }
        }
        // 12 wrong codes > ACCOUNT_LIMIT (10): a fresh pending step is refused too.
        $this->login();
        $env = $this->api('auth.2fa_verify', ['code' => $this->codeFor($secret)]);

        $this->assertSame('locked', $env['error']['code'] ?? null);
        $this->assertSame(0, $this->sessions());
        $this->assertSame(1, $this->logCount('Two-factor locked'));
    }

    public function testVerifyWithoutAPendingStepIsExpired(): void
    {
        $env = $this->api('auth.2fa_verify', ['code' => '123456']);
        $this->assertSame('?p=login&m=2fa_expired', $env['redirect'] ?? null);

        $_COOKIE[TwoFactor::PENDING_COOKIE] = str_repeat('A', 43);
        $env = $this->api('auth.2fa_verify', ['code' => '123456']);
        $this->assertSame('?p=login&m=2fa_expired', $env['redirect'] ?? null, 'A made-up token is no pending step.');
    }

    public function testExpiredPendingStepIsRefused(): void
    {
        $secret = $this->enroll();
        $this->login();
        Fixture::rawPdo()->exec('UPDATE `' . DB_PREFIX . '_auth_pending` SET expires = ' . (time() - 1));

        $env = $this->api('auth.2fa_verify', ['code' => $this->codeFor($secret)]);

        $this->assertSame('?p=login&m=2fa_expired', $env['redirect'] ?? null);
        $this->assertSame(0, $this->sessions());
    }

    public function testEnrolPendingStepCannotBeUsedToVerifyAndViceVersa(): void
    {
        $this->setRequirement(TwoFactor::REQUIRE_ALL);
        $this->login();
        $env = $this->api('auth.2fa_verify', ['code' => '123456']);
        $this->assertSame('?p=login&m=2fa_expired', $env['redirect'] ?? null);
    }

    // -- Required by the setting ----------------------------------------

    public function testOwnersSettingSendsAnOwnerWithout2faToSetup(): void
    {
        $this->setRequirement(TwoFactor::REQUIRE_OWNERS);

        $env = $this->login();

        $this->assertSame('?p=login&step=enroll', $env['redirect'] ?? null);
        $this->assertSame(0, $this->sessions());

        $start = $this->api('auth.2fa_enroll_start', []);
        $this->assertTrue($start['ok'] ?? false, json_encode($start));
        $done = $this->api('auth.2fa_enroll_confirm', ['code' => $this->codeFor($start['data']['secret'])]);
        $this->assertTrue($done['ok'] ?? false, json_encode($done));
        $this->assertCount(TwoFactor::RECOVERY_CODES, $done['data']['recovery_codes']);
        $this->assertSame('?', $done['data']['next']);
        $this->assertSame(1, $this->sessions());
        $this->assertTrue($this->tf()->isEnrolled(Fixture::adminAid()));
    }

    public function testOwnersSettingLeavesOtherAdminsAloneButAllCoversThem(): void
    {
        $aid = $this->seedAdmin('mod107', 'modpass107', 0);

        $this->setRequirement(TwoFactor::REQUIRE_OWNERS);
        $this->assertFalse($this->tf()->isRequiredFor($aid));
        $this->assertTrue($this->tf()->isRequiredFor(Fixture::adminAid()));
        $this->assertSame('?', $this->login('mod107', 'modpass107')['redirect'] ?? null);

        $this->setRequirement(TwoFactor::REQUIRE_ALL);
        $this->assertTrue($this->tf()->isRequiredFor($aid));
        $this->assertSame('?p=login&step=enroll', $this->login('mod107', 'modpass107')['redirect'] ?? null);
    }

    public function testOwnerFlagFromTheWebGroupCounts(): void
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare('INSERT INTO `' . DB_PREFIX . '_groups` (type, name, flags) VALUES (1, ?, ?)')
            ->execute(['owners107', \WebPermission::Owner->value]);
        $gid = (int) $pdo->lastInsertId();
        $aid = $this->seedAdmin('grpowner107', 'grppass107', 0, $gid);

        $this->setRequirement(TwoFactor::REQUIRE_OWNERS);

        $this->assertTrue($this->tf()->isRequiredFor($aid));
    }

    public function testCannotTurnOffWhileRequired(): void
    {
        $secret = $this->enroll();
        $this->setRequirement(TwoFactor::REQUIRE_OWNERS);
        $this->loginAsAdmin();

        $env = $this->api('account.2fa_disable', ['password' => 'admin', 'code' => $this->codeFor($secret, 1)]);

        $this->assertSame('required', $env['error']['code'] ?? null);
        $this->assertTrue($this->tf()->isEnrolled(Fixture::adminAid()));
    }

    // -- Turn off / recovery codes / reset ------------------------------

    public function testTurnOffNeedsPasswordAndCode(): void
    {
        $secret = $this->enroll();
        $this->loginAsAdmin();

        $this->assertSame('bad_password', $this->api('account.2fa_disable', ['password' => 'x', 'code' => '000000'])['error']['code'] ?? null);
        $this->assertSame('invalid_code', $this->api('account.2fa_disable', ['password' => 'admin', 'code' => '000000'])['error']['code'] ?? null);
        $this->assertTrue($this->tf()->isEnrolled(Fixture::adminAid()));

        $ok = $this->api('account.2fa_disable', ['password' => 'admin', 'code' => $this->codeFor($secret, 1)]);
        $this->assertTrue($ok['ok'] ?? false, json_encode($ok));
        $this->assertFalse($this->tf()->isEnrolled(Fixture::adminAid()));
        $this->assertSame([], $this->rows('admin_recovery_codes', ['aid' => Fixture::adminAid()]));
    }

    public function testAccountActionsAreThrottled(): void
    {
        $this->enroll();
        $this->loginAsAdmin();
        for ($i = 0; $i < TwoFactor::ACCOUNT_LIMIT; $i++) {
            $this->api('account.2fa_recovery_codes', ['code' => '000000']);
        }

        $env = $this->api('account.2fa_recovery_codes', ['code' => '000000']);

        $this->assertSame('locked', $env['error']['code'] ?? null, 'A stolen session cannot brute-force codes here.');
    }

    public function testNewRecoveryCodesReplaceTheOldOnes(): void
    {
        $secret = $this->enroll();
        $old = $this->lastRecoveryCodes;
        $this->loginAsAdmin();

        $env = $this->api('account.2fa_recovery_codes', ['code' => $this->codeFor($secret, 1)]);

        $this->assertTrue($env['ok'] ?? false, json_encode($env));
        $this->assertCount(TwoFactor::RECOVERY_CODES, $env['data']['recovery_codes']);
        $this->assertFalse($this->tf()->useRecoveryCode(Fixture::adminAid(), $old[0], time()), 'Old codes stop working.');
        $this->assertTrue($this->tf()->useRecoveryCode(Fixture::adminAid(), $env['data']['recovery_codes'][0], time()));
    }

    public function testOwnerResetsAnotherAdminButNotThemself(): void
    {
        $aid = $this->seedAdmin('mod107', 'modpass107', 0);
        $this->tf()->beginSetup($aid, 'mod107');
        $secret = (string) SecretBox::open((string) $this->row('admin_totp', ['aid' => $aid])['secret'], 'totp');
        $this->assertNotNull($this->tf()->confirmSetup($aid, $this->codeFor($secret), time()));

        $this->loginAsAdmin();
        $self = $this->api('admins.2fa_reset', ['aid' => Fixture::adminAid()]);
        $this->assertSame('forbidden', $self['error']['code'] ?? null);

        $env = $this->api('admins.2fa_reset', ['aid' => $aid]);
        $this->assertTrue($env['ok'] ?? false, json_encode($env));
        $this->assertFalse($this->tf()->isEnrolled($aid));
        $this->assertSame(1, $this->logCount('Two-factor reset'));
    }

    public function testResetIsOwnerOnly(): void
    {
        $aid = $this->seedAdmin('mod107', 'modpass107', \WebPermission::EditAdmins->value);
        $this->loginAs($aid);

        $env = $this->api('admins.2fa_reset', ['aid' => Fixture::adminAid()]);

        $this->assertSame('forbidden', $env['error']['code'] ?? null);
    }

    public function testDeletingAnAdminDeletesTheir2fa(): void
    {
        $aid = $this->seedAdmin('mod107', 'modpass107', 0);
        $this->tf()->beginSetup($aid, 'mod107');
        $this->loginAsAdmin();

        $this->api('admins.remove', ['aid' => $aid]);

        $this->assertNull($this->row('admin_totp', ['aid' => $aid]));
    }

    // -- Every sign-in path goes through the second step ----------------

    public function testNoSignInPathStartsASessionDirectly(): void
    {
        $normal = (string) php_strip_whitespace(ROOT . 'includes/Auth/Handler/NormalAuthHandler.php');
        $steam = (string) php_strip_whitespace(ROOT . 'includes/Auth/Handler/SteamAuthHandler.php');
        $this->assertStringNotContainsString('Auth::login(', $normal);
        $this->assertStringNotContainsString('Auth::login(', $steam);
        $this->assertStringContainsString('->completePrimary(', $steam);

        $auth = (string) php_strip_whitespace(ROOT . 'api/handlers/auth.php');
        $this->assertStringNotContainsString('Auth::login(', $auth);
        $this->assertStringContainsString('->completePrimary($auth->aid()', $auth);
    }

    // -- Helpers --------------------------------------------------------

    /** @var list<string> */
    private array $lastRecoveryCodes = [];

    private function tf(): TwoFactor
    {
        return new TwoFactor($GLOBALS['PDO']);
    }

    /** Turn 2FA on for the fixture admin; returns the secret. */
    private function enroll(): string
    {
        $tf = $this->tf();
        $setup = $tf->beginSetup(Fixture::adminAid(), 'admin');
        $this->assertNotNull($setup);
        $codes = $tf->confirmSetup(Fixture::adminAid(), $this->codeFor($setup['secret']), time());
        $this->assertNotNull($codes);
        $this->lastRecoveryCodes = $codes;
        return $setup['secret'];
    }

    /**
     * A valid code: the current step, or `$ahead` steps later (still in
     * the ±1 window) when an earlier code of the same step was used.
     */
    private function codeFor(string $secret, int $ahead = 0): string
    {
        return Totp::code($secret, Totp::step(time()) + $ahead);
    }

    /** @return array<string, mixed> */
    private function login(string $user = 'admin', string $pass = 'admin'): array
    {
        unset($_COOKIE[TwoFactor::PENDING_COOKIE]);
        return $this->api('auth.login', ['username' => $user, 'password' => $pass]);
    }

    private function sessions(): int
    {
        return (int) Fixture::rawPdo()->query('SELECT COUNT(*) FROM `' . DB_PREFIX . '_login_tokens`')->fetchColumn();
    }

    private function setRequirement(string $value): void
    {
        Fixture::rawPdo()->prepare('REPLACE INTO `' . DB_PREFIX . '_settings` (setting, value) VALUES (?, ?)')
            ->execute([TwoFactor::SETTING, $value]);
        \Config::init($GLOBALS['PDO']);
    }

    private function seedAdmin(string $user, string $pass, int $flags, int $gid = -1): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(
            'INSERT INTO `' . DB_PREFIX . '_admins` (user, authid, password, gid, email, extraflags, immunity, srv_group, srv_flags, srv_password)'
            . " VALUES (?, ?, ?, ?, ?, ?, 0, '', '', '')"
        )->execute([$user, 'STEAM_0:1:107' . random_int(100, 999), password_hash($pass, PASSWORD_BCRYPT), $gid, $user . '@example.test', $flags]);
        return (int) $pdo->lastInsertId();
    }

    private function logCount(string $title): int
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT COUNT(*) FROM `' . DB_PREFIX . '_log` WHERE title = ?');
        $stmt->execute([$title]);
        return (int) $stmt->fetchColumn();
    }
}
