<?php

namespace Sbpp\Tests\Api;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Sbpp\Tests\Fixture;

final class RestSessionTest extends TestCase
{
    public function testV1EntryDefinesRestFlagBeforeInit(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 2) . '/api/v1.php');
        $definePos = strpos($src, "define('SBPP_REST'");
        $includePos = strpos($src, "include_once dirname(__DIR__) . '/init.php'");
        $this->assertNotFalse($definePos);
        $this->assertNotFalse($includePos);
        $this->assertLessThan($includePos, $definePos);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCsrfInitDoesNotStartSessionWhenRestFlagIsSet(): void
    {
        if (!defined('SBPP_REST')) {
            define('SBPP_REST', true);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        $this->assertNotSame(PHP_SESSION_ACTIVE, session_status());
        \CSRF::init();
        $this->assertNotSame(PHP_SESSION_ACTIVE, session_status());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAuthVerifyDoesNotReadCookieWhenRestFlagIsSet(): void
    {
        if (!defined('SBPP_REST')) {
            define('SBPP_REST', true);
        }
        Fixture::reset();

        $jti = \Sbpp\Security\Crypto::genJTI();
        $past = time() - 120;
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_login_tokens` (jti, secret, lastAccessed) VALUES (?, ?, ?)',
            DB_PREFIX
        ))->execute([$jti, 'test-secret', $past]);

        $token = \Sbpp\Auth\JWT::create($jti, 3600, Fixture::adminAid());
        $_COOKIE['sbpp_auth'] = $token->toString();

        $this->assertNull(\Auth::verify());

        $stmt = $pdo->prepare(sprintf(
            'SELECT lastAccessed FROM `%s_login_tokens` WHERE jti = ?',
            DB_PREFIX
        ));
        $stmt->execute([$jti]);
        $this->assertSame($past, (int) $stmt->fetchColumn());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAuthVerifySlidesSessionWhenRestFlagIsNotSet(): void
    {
        $this->assertFalse(defined('SBPP_REST'));
        Fixture::reset();

        $jti = \Sbpp\Security\Crypto::genJTI();
        $past = time() - 120;
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_login_tokens` (jti, secret, lastAccessed) VALUES (?, ?, ?)',
            DB_PREFIX
        ))->execute([$jti, 'test-secret', $past]);

        $token = \Sbpp\Auth\JWT::create($jti, 3600, Fixture::adminAid());
        $_COOKIE['sbpp_auth'] = $token->toString();

        $verified = \Auth::verify();
        $this->assertNotNull($verified);

        $stmt = $pdo->prepare(sprintf(
            'SELECT lastAccessed FROM `%s_login_tokens` WHERE jti = ?',
            DB_PREFIX
        ));
        $stmt->execute([$jti]);
        $this->assertGreaterThan($past, (int) $stmt->fetchColumn());
    }
}
