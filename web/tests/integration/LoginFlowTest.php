<?php

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;

/**
 * Tier 1 smoke flow #5 from #1095: the Plogin handler. Hits auth.login
 * with bad creds and verifies the lockout counter increments (the
 * `:prefix_auth_throttle` name counter since #106).
 */
final class LoginFlowTest extends ApiTestCase
{
    public function testFailedLoginIncrementsAttempts(): void
    {
        // Enable normal login (default in install/data.sql).
        \Config::init($GLOBALS['PDO']);

        $env = $this->api('auth.login', ['username' => 'admin', 'password' => 'wrong']);
        $this->assertSame('?p=login&m=failed', $env['redirect'] ?? null);

        $this->assertSame(1, $this->nameAttempts('admin'));
    }

    /** Failed attempts on the shared `n:` counter of a username (#106). */
    private function nameAttempts(string $user): int
    {
        $key = 'n:' . (new \Sbpp\Auth\LoginThrottle($GLOBALS['PDO']))->nameKey($user, true);
        $stmt = \Sbpp\Tests\Fixture::rawPdo()->prepare(
            'SELECT attempts FROM `' . DB_PREFIX . '_auth_throttle` WHERE throttle_key = ?'
        );
        $stmt->execute([$key]);
        return (int) $stmt->fetchColumn();
    }
}
