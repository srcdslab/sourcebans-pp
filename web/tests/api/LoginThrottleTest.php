<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Tests\Api;

use Sbpp\Auth\LoginThrottle;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #97: the login lockout is reserved in one statement before the password
 * check, and a per-address limit covers attempts spread across usernames.
 */
final class LoginThrottleTest extends ApiTestCase
{
    private const IP = '203.0.113.7';

    /** @var array<string, mixed> */
    private array $server;

    protected function setUp(): void
    {
        parent::setUp();
        $this->server = $_SERVER;
        $_SERVER['REMOTE_ADDR'] = self::IP;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
        parent::tearDown();
    }

    public function testKeyGroupsIpv6By64AndUnwrapsMappedIpv4(): void
    {
        $this->assertSame('cb007107', LoginThrottle::key('203.0.113.7'));
        $this->assertSame(LoginThrottle::key('203.0.113.7'), LoginThrottle::key('::ffff:203.0.113.7'));
        $this->assertSame(
            LoginThrottle::key('2001:db8:1:2::1'),
            LoginThrottle::key('2001:db8:1:2:ffff:ffff:ffff:ffff'),
            'Addresses in the same /64 share a counter.',
        );
        $this->assertNotSame(LoginThrottle::key('2001:db8:1:2::1'), LoginThrottle::key('2001:db8:1:3::1'));
        $this->assertSame(16, strlen((string) LoginThrottle::key('2001:db8::1')));
        $this->assertNull(LoginThrottle::key(''));
        $this->assertNull(LoginThrottle::key('not-an-ip'));
    }

    public function testDefaultLimit(): void
    {
        $this->assertFalse(defined('SBPP_LOGIN_IP_LIMIT'), 'The test run uses the default limit.');
        $this->assertSame(LoginThrottle::DEFAULT_LIMIT, LoginThrottle::limit());
    }

    public function testFailedLoginsAreCountedPerAddressForUnknownUsersToo(): void
    {
        $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'nobody-97', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'someone-else-97', 'password' => 'wrong']);

        $this->assertSame(3, $this->ipAttempts());
    }

    public function testAddressOverTheLimitIsRefusedEvenWithTheRightPassword(): void
    {
        $this->seedIpRow(LoginThrottle::DEFAULT_LIMIT, time());

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
        $admin = $this->row('admins', ['user' => 'admin']);
        $this->assertSame(0, (int) $admin['attempts'], 'A refused address must not touch the account.');
    }

    public function testAddressLimitAnswersTheSameForKnownAndUnknownUsers(): void
    {
        $this->seedIpRow(LoginThrottle::DEFAULT_LIMIT, time());
        $known = $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $unknown = $this->api('auth.login', ['username' => 'nobody-97', 'password' => 'wrong']);

        $this->assertSame($known, $unknown);
    }

    public function testOtherAddressesAreNotAffected(): void
    {
        $this->seedIpRow(LoginThrottle::DEFAULT_LIMIT, time());
        $_SERVER['REMOTE_ADDR'] = '198.51.100.9';

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame('?', $env['redirect'] ?? null);
    }

    public function testExpiredWindowStartsOver(): void
    {
        $this->seedIpRow(LoginThrottle::DEFAULT_LIMIT + 5, time() - LoginThrottle::WINDOW_SECONDS - 1);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame('?', $env['redirect'] ?? null);
        $this->assertSame(0, $this->ipAttempts(), 'The success gives back the one attempt of the new window.');
    }

    public function testSuccessfulLoginGivesItsAttemptBack(): void
    {
        $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame(1, $this->ipAttempts(), 'Only the failure stays counted.');
    }

    public function testLockSetByAnotherRequestRefusesWithoutCheckingThePassword(): void
    {
        // What a parallel request sees once another one took the last
        // slot: the lock is set while `attempts` may still be low.
        $until = date('Y-m-d H:i:s', time() + 600);
        Fixture::rawPdo()->prepare('UPDATE `' . DB_PREFIX . '_admins` SET attempts = 0, lockout_until = ? WHERE aid = ?')
            ->execute([$until, Fixture::adminAid()]);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
        $admin = $this->row('admins', ['user' => 'admin']);
        $this->assertSame(0, (int) $admin['attempts'], 'No slot may be taken while locked.');
    }

    public function testLastAllowedAttemptStillChecksThePasswordAndClearsTheLock(): void
    {
        // The 5th reservation sets the lock before the password check;
        // the right password must still log in and clear it.
        Fixture::rawPdo()->prepare('UPDATE `' . DB_PREFIX . '_admins` SET attempts = 4 WHERE aid = ?')
            ->execute([Fixture::adminAid()]);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame('?', $env['redirect'] ?? null);
        $admin = $this->row('admins', ['user' => 'admin']);
        $this->assertSame(0, (int) $admin['attempts']);
        $this->assertNull($admin['lockout_until']);
    }

    public function testMissingTableFailsOpenUntilTheUpdaterRuns(): void
    {
        // Between uploading a release and running migration 818.
        $table = DB_PREFIX . '_login_throttle';
        Fixture::rawPdo()->exec("DROP TABLE `{$table}`");
        try {
            $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
            $this->assertSame('?', $env['redirect'] ?? null);
        } finally {
            Fixture::rawPdo()->exec(
                "CREATE TABLE IF NOT EXISTS `{$table}` (`ip` varchar(32) NOT NULL, `attempts` int(10) UNSIGNED NOT NULL DEFAULT 0,"
                . ' `window_start` int(11) NOT NULL, PRIMARY KEY (`ip`), KEY `window_start` (`window_start`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
            );
        }
    }

    public function testReservationRunsBeforeThePasswordCheck(): void
    {
        $src = (string) php_strip_whitespace(ROOT . 'api/handlers/auth.php');
        $start = (int) strpos($src, 'function api_auth_login(');
        $body = substr($src, $start, (int) strpos($src, 'function _api_auth_locked_redirect(') - $start);

        $reserveIp = strpos($body, '$throttle->reserve(');
        $lookup = strpos($body, '_api_auth_get_user($username)');
        $reserveAccount = strpos($body, 'attempts = attempts + 1');
        $verify = strpos($body, 'new NormalAuthHandler(');
        $this->assertNotFalse($reserveIp);
        $this->assertNotFalse($reserveAccount);
        $this->assertNotFalse($verify);
        $this->assertLessThan($lookup, $reserveIp, 'The address limit must not depend on the username.');
        $this->assertLessThan($verify, $reserveAccount, 'The account attempt must be reserved before the password check.');
        $this->assertStringContainsString('WHERE aid = :aid AND (lockout_until IS NULL OR lockout_until <= :now)', $body);
    }

    private function seedIpRow(int $attempts, int $windowStart): void
    {
        Fixture::rawPdo()->prepare(
            'INSERT INTO `' . DB_PREFIX . '_login_throttle` (ip, attempts, window_start) VALUES (?, ?, ?)'
        )->execute([LoginThrottle::key(self::IP), $attempts, $windowStart]);
    }

    private function ipAttempts(): int
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT attempts FROM `' . DB_PREFIX . '_login_throttle` WHERE ip = ?');
        $stmt->execute([LoginThrottle::key(self::IP)]);
        return (int) $stmt->fetchColumn();
    }
}
