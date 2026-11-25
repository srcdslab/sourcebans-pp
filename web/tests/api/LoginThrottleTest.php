<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Tests\Api;

use Sbpp\Auth\DeviceCookie;
use Sbpp\Auth\LoginThrottle;
use Sbpp\Auth\ThrottleUnavailable;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * Sign-in counters: per address (#97), per username and per device cookie
 * (#106), all taken before the password check.
 */
final class LoginThrottleTest extends ApiTestCase
{
    private const IP = '203.0.113.7';
    private const ATTACKER_IP = '198.51.100.66';

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
        unset($_COOKIE[DeviceCookie::COOKIE]);
        parent::tearDown();
    }

    // -- Per address (#97) ----------------------------------------------

    public function testAddressKeyGroupsIpv6By64AndUnwrapsMappedIpv4(): void
    {
        $this->assertSame('cb007107', LoginThrottle::addressKey('203.0.113.7'));
        $this->assertSame(LoginThrottle::addressKey('203.0.113.7'), LoginThrottle::addressKey('::ffff:203.0.113.7'));
        $this->assertSame(
            LoginThrottle::addressKey('2001:db8:1:2::1'),
            LoginThrottle::addressKey('2001:db8:1:2:ffff:ffff:ffff:ffff'),
            'Addresses in the same /64 share a counter.',
        );
        $this->assertNotSame(LoginThrottle::addressKey('2001:db8:1:2::1'), LoginThrottle::addressKey('2001:db8:1:3::1'));
        $this->assertSame(16, strlen((string) LoginThrottle::addressKey('2001:db8::1')));
        $this->assertNull(LoginThrottle::addressKey(''));
        $this->assertNull(LoginThrottle::addressKey('not-an-ip'));
    }

    public function testDefaultLimit(): void
    {
        $this->assertFalse(defined('SBPP_LOGIN_IP_LIMIT'), 'The test run uses the default limit.');
        $this->assertSame(LoginThrottle::DEFAULT_LIMIT, LoginThrottle::ipLimit());
    }

    public function testFailedLoginsAreCountedPerAddressForUnknownUsersToo(): void
    {
        $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'nobody-97', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'someone-else-97', 'password' => 'wrong']);

        $this->assertSame(3, $this->attempts($this->ipKey()));
    }

    public function testAddressOverTheLimitIsRefusedEvenWithTheRightPassword(): void
    {
        $this->seed($this->ipKey(), LoginThrottle::DEFAULT_LIMIT);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
        $this->assertSame(0, $this->attempts($this->nameKey('admin')), 'A refused address must not reach the name counter.');
    }

    public function testAddressLimitAnswersTheSameForKnownAndUnknownUsers(): void
    {
        $this->seed($this->ipKey(), LoginThrottle::DEFAULT_LIMIT);
        $known = $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $unknown = $this->api('auth.login', ['username' => 'nobody-97', 'password' => 'wrong']);

        $this->assertSame($known, $unknown);
    }

    public function testOtherAddressesAreNotAffected(): void
    {
        $this->seed($this->ipKey(), LoginThrottle::DEFAULT_LIMIT);
        $_SERVER['REMOTE_ADDR'] = '198.51.100.9';

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame('?', $env['redirect'] ?? null);
    }

    public function testExpiredWindowStartsOver(): void
    {
        $this->seed($this->ipKey(), LoginThrottle::DEFAULT_LIMIT + 5, time() - 1);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame('?', $env['redirect'] ?? null);
        $this->assertSame(0, $this->attempts($this->ipKey()), 'The success gives back the one attempt of the new window.');
    }

    public function testSuccessfulLoginGivesItsAttemptBack(): void
    {
        $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame(1, $this->attempts($this->ipKey()), 'Only the failure stays counted.');
        $this->assertSame(1, $this->attempts($this->nameKey('admin')));
    }

    public function testAddressLimitWritesOneAuditEntryPerWindow(): void
    {
        $this->seed($this->ipKey(), LoginThrottle::DEFAULT_LIMIT);

        for ($i = 0; $i < 3; $i++) {
            $this->api('auth.login', ['username' => 'nobody-' . $i, 'password' => 'wrong']);
        }

        $this->assertSame(1, $this->logCount('Sign-in throttled'));
    }

    // -- Per username (#106) --------------------------------------------

    public function testNameLocksAfterFiveFailuresEvenWithTheRightPassword(): void
    {
        $this->fail5('admin');

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
    }

    public function testUnknownNamesLockLikeRealOnesSoLockedIsNoOracle(): void
    {
        $this->fail5('admin');
        $this->fail5('no-such-admin-106');

        $known = $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $unknown = $this->api('auth.login', ['username' => 'no-such-admin-106', 'password' => 'wrong']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $known['redirect'] ?? '');
        $this->assertSame($known, $unknown);
    }

    public function testCaseAccentAndTrailingSpaceVariantsShareTheAccountCounter(): void
    {
        // `WHERE user = :user` matches all of these to `admin`
        // (utf8mb4_general_ci, PAD SPACE): separate counters would give
        // unlimited guesses by rotating variants.
        foreach (['ADMIN', 'Admin', 'ádmin', 'admin ', 'ÁDMIN  '] as $variant) {
            $this->api('auth.login', ['username' => $variant, 'password' => 'wrong']);
        }

        $this->assertSame(5, $this->attempts($this->nameKey('admin')));
        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
    }

    public function testUnknownNameVariantsShareACounterToo(): void
    {
        foreach (['ghost-106', 'GHOST-106', 'ghóst-106', 'ghost-106 ', 'Ghost-106'] as $variant) {
            $this->api('auth.login', ['username' => $variant, 'password' => 'wrong']);
        }

        $env = $this->api('auth.login', ['username' => 'ghost-106', 'password' => 'wrong']);
        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
    }

    public function testNameLockIsSharedAcrossAddresses(): void
    {
        // A botnet spreading guesses over addresses still gets 5 per window.
        for ($i = 0; $i < 5; $i++) {
            $_SERVER['REMOTE_ADDR'] = '198.51.100.' . (10 + $i);
            $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        }
        $_SERVER['REMOTE_ADDR'] = '198.51.100.99';

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '');
    }

    public function testNameLockWritesOneAuditEntryForARealAccountOnly(): void
    {
        $this->fail5('admin');
        $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->fail5('no-such-admin-106');
        $this->api('auth.login', ['username' => 'no-such-admin-106', 'password' => 'wrong']);

        $this->assertSame(1, $this->logCount('Sign-in locked'));
    }

    // -- Device cookies (#106) ------------------------------------------

    public function testSuccessfulLoginIssuesADeviceCookieBoundToTheName(): void
    {
        $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertNotNull(DeviceCookie::nonceFor($this->nameHash('admin'), time()));
        $this->assertNull(DeviceCookie::nonceFor($this->nameHash('someone-else'), time()), 'Bound to one name.');
    }

    public function testTheAdminsOwnBrowserStillSignsInWhileAnAttackerLockedTheName(): void
    {
        // The admin signed in from this browser before.
        $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $adminCookie = $_COOKIE[DeviceCookie::COOKIE];

        // An attacker without the cookie fills the shared counter.
        unset($_COOKIE[DeviceCookie::COOKIE]);
        $_SERVER['REMOTE_ADDR'] = self::ATTACKER_IP;
        $this->fail5('admin');
        $locked = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $this->assertStringStartsWith('?p=login&m=locked&time=', $locked['redirect'] ?? '');

        // The admin, back on their browser.
        $_COOKIE[DeviceCookie::COOKIE] = $adminCookie;
        $_SERVER['REMOTE_ADDR'] = self::IP;
        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertSame('?', $env['redirect'] ?? null);
    }

    public function testATrustedBrowserHasItsOwnBudgetAndDoesNotFillTheSharedOne(): void
    {
        $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->fail5('admin');
        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);

        $this->assertStringStartsWith('?p=login&m=locked&time=', $env['redirect'] ?? '', 'The device locks after 5 failures.');
        $this->assertSame(0, $this->attempts($this->nameKey('admin')), 'Device failures stay off the shared counter.');

        unset($_COOKIE[DeviceCookie::COOKIE]);
        $other = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $this->assertSame('?', $other['redirect'] ?? null, 'Other browsers are not locked by one device.');
    }

    public function testForgedExpiredOrForeignDeviceCookiesAreIgnored(): void
    {
        $name = $this->nameHash('admin');
        $nonce = str_repeat('A', 22);
        $now = time();

        $_COOKIE[DeviceCookie::COOKIE] = DeviceCookie::build($name, $now, $nonce);
        $this->assertSame($nonce, DeviceCookie::nonceFor($name, $now), 'Sanity: a genuine cookie verifies.');

        $_COOKIE[DeviceCookie::COOKIE] = 'v1.' . $now . '.' . $nonce . '.' . str_repeat('A', 43);
        $this->assertNull(DeviceCookie::nonceFor($name, $now), 'Forged MAC.');

        $_COOKIE[DeviceCookie::COOKIE] = DeviceCookie::build($name, $now - DeviceCookie::LIFETIME, $nonce);
        $this->assertNull(DeviceCookie::nonceFor($name, $now), 'Expired.');

        $_COOKIE[DeviceCookie::COOKIE] = DeviceCookie::build($this->nameHash('someone-else'), $now, $nonce);
        $this->assertNull(DeviceCookie::nonceFor($name, $now), 'Issued for another name.');

        $_COOKIE[DeviceCookie::COOKIE] = ['v1'];
        $this->assertNull(DeviceCookie::nonceFor($name, $now), 'Array-shaped cookie.');

        // A forged cookie must not dodge the shared counter.
        $_COOKIE[DeviceCookie::COOKIE] = 'v1.' . $now . '.' . $nonce . '.' . str_repeat('A', 43);
        $this->fail5('admin');
        $this->assertSame(5, $this->attempts($this->nameKey('admin')));
    }

    // -- Fail closed (#106) ---------------------------------------------

    public function testMissingTableRefusesPasswordSignIn(): void
    {
        // Between uploading a release and running migration 819: pre-#106
        // the login went through uncounted.
        $table = DB_PREFIX . '_auth_throttle';
        Fixture::rawPdo()->exec("DROP TABLE `{$table}`");
        try {
            $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
            $this->assertSame('?p=login&m=unavailable', $env['redirect'] ?? null);

            $unknown = $this->api('auth.login', ['username' => 'nobody-106', 'password' => 'x']);
            $this->assertSame($env, $unknown, 'Same answer for every name.');
        } finally {
            Fixture::rawPdo()->exec(
                "CREATE TABLE IF NOT EXISTS `{$table}` (`throttle_key` varchar(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,"
                . ' `attempts` int(10) UNSIGNED NOT NULL DEFAULT 0, `expires` int(11) NOT NULL,'
                . ' PRIMARY KEY (`throttle_key`), KEY `expires` (`expires`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
            );
        }
    }

    public function testOtherDatabaseErrorsDoNotSayRunTheUpdater(): void
    {
        // A table that exists but can't be written stands in for a deadlock
        // or a lock wait timeout: still refused, without "run the updater".
        $table = DB_PREFIX . '_auth_throttle';
        $pdo = Fixture::rawPdo();
        $pdo->exec("DROP TABLE `{$table}`");
        $pdo->exec("CREATE TABLE `{$table}` (`throttle_key` varchar(80) NOT NULL PRIMARY KEY) ENGINE=InnoDB");
        try {
            $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
            $this->assertSame('?p=login&m=signin_error', $env['redirect'] ?? null);
        } finally {
            $pdo->exec("DROP TABLE `{$table}`");
            $pdo->exec(
                "CREATE TABLE `{$table}` (`throttle_key` varchar(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,"
                . ' `attempts` int(10) UNSIGNED NOT NULL DEFAULT 0, `expires` int(11) NOT NULL,'
                . ' PRIMARY KEY (`throttle_key`), KEY `expires` (`expires`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
            );
        }
    }

    public function testOnlyAMissingTableCountsAsTableMissing(): void
    {
        $missing = new \PDOException('Table does not exist');
        $missing->errorInfo = ['42S02', 1146, "Table 'x.sb_auth_throttle' doesn't exist"];
        $deadlock = new \PDOException('Deadlock');
        $deadlock->errorInfo = ['40001', 1213, 'Deadlock found when trying to get lock'];

        $this->assertTrue(ThrottleUnavailable::fromPdo('t', $missing)->tableMissing);
        $this->assertFalse(ThrottleUnavailable::fromPdo('t', $deadlock)->tableMissing);
    }

    // -- Concurrency ----------------------------------------------------

    public function testConcurrentHitsEachGetTheirOwnCount(): void
    {
        // The audit entry is written by the attempt that sees exactly
        // limit + 1. Pre-fix, hit() read the row back after its write, so
        // parallel attempts could all read a higher count and none saw
        // limit + 1. Each attempt must get the count its own write made:
        // over all of them, every number exactly once.
        $workers = 6;
        $hits = 30;
        $key = 'test:concurrent';
        $env = [
            'PATH' => (string) getenv('PATH'),
            'DB_HOST' => DB_HOST, 'DB_PORT' => (string) DB_PORT, 'DB_NAME' => DB_NAME,
            'DB_USER' => DB_USER, 'DB_PASS' => DB_PASS, 'DB_PREFIX' => DB_PREFIX, 'DB_CHARSET' => DB_CHARSET,
        ];
        $startAt = sprintf('%.6F', microtime(true) + 1.5);

        $procs = [];
        for ($w = 0; $w < $workers; $w++) {
            $pipes = [];
            $proc = proc_open(
                [PHP_BINARY, ROOT . 'tests/scripts/throttle-hit-worker.php', $key, (string) $hits, $startAt],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                null,
                $env,
            );
            $this->assertIsResource($proc);
            $procs[] = [$proc, $pipes];
        }

        $counts = [];
        foreach ($procs as [$proc, $pipes]) {
            $out = (string) stream_get_contents($pipes[1]);
            $err = (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $this->assertSame(0, proc_close($proc), $err);
            foreach (preg_split('/\R/', trim($out)) ?: [] as $line) {
                $counts[] = (int) $line;
            }
        }
        sort($counts);

        $this->assertSame(range(1, $workers * $hits), $counts);
        $this->assertSame($workers * $hits, $this->attempts($key));
    }

    public function testCountersAreTakenBeforeThePasswordCheck(): void
    {
        $src = (string) php_strip_whitespace(ROOT . 'api/handlers/auth.php');
        $start = (int) strpos($src, 'function api_auth_login(');
        $body = substr($src, $start, (int) strpos($src, 'function _api_auth_locked_redirect(') - $start);

        $ipHit = strpos($body, '$throttle->hit($ipCounter');
        $lookup = strpos($body, '_api_auth_get_user($username)');
        $nameHit = strpos($body, '$throttle->hit($counter');
        $dummy = strpos($body, 'password_verify($password, API_AUTH_TIMING_DUMMY_HASH)');
        $verify = strpos($body, 'new NormalAuthHandler(');
        foreach ([$ipHit, $lookup, $nameHit, $dummy, $verify] as $pos) {
            $this->assertNotFalse($pos);
        }
        $this->assertLessThan($lookup, $ipHit, 'The address limit must not depend on the username.');
        $this->assertLessThan($dummy, $nameHit, 'Unknown names must be counted before answering.');
        $this->assertLessThan($verify, $nameHit, 'The name attempt must be taken before the password check.');
    }

    // -- Helpers --------------------------------------------------------

    private function fail5(string $user): void
    {
        for ($i = 0; $i < LoginThrottle::ACCOUNT_LIMIT; $i++) {
            $env = $this->api('auth.login', ['username' => $user, 'password' => 'wrong']);
            $this->assertSame('?p=login&m=failed', $env['redirect'] ?? null, "attempt $i on $user");
        }
    }

    private function ipKey(): string
    {
        return 'ip:' . LoginThrottle::addressKey((string) $_SERVER['REMOTE_ADDR']);
    }

    private function nameHash(string $user): string
    {
        return (new LoginThrottle($GLOBALS['PDO']))->nameKey($user, true);
    }

    private function nameKey(string $user): string
    {
        return 'n:' . $this->nameHash($user);
    }

    private function seed(string $key, int $attempts, ?int $expires = null): void
    {
        Fixture::rawPdo()->prepare(
            'INSERT INTO `' . DB_PREFIX . '_auth_throttle` (throttle_key, attempts, expires) VALUES (?, ?, ?)'
        )->execute([$key, $attempts, $expires ?? time() + LoginThrottle::WINDOW_SECONDS]);
    }

    private function attempts(string $key): int
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT attempts FROM `' . DB_PREFIX . '_auth_throttle` WHERE throttle_key = ?');
        $stmt->execute([$key]);
        return (int) $stmt->fetchColumn();
    }

    private function logCount(string $title): int
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT COUNT(*) FROM `' . DB_PREFIX . '_log` WHERE title = ?');
        $stmt->execute([$title]);
        return (int) $stmt->fetchColumn();
    }
}
