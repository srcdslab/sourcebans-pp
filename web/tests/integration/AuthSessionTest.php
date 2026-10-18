<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Auth\JWT;
use Sbpp\Security\Crypto;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #54: browser sessions expire and can be revoked server-side.
 *
 * Pre-fix `JWT::validate()` never checked time claims, `login_tokens` was
 * never written, and `logout()` only cleared the cookie, so a leaked
 * `sbpp_auth` cookie stayed valid until SB_SECRET_KEY was rotated.
 */
final class AuthSessionTest extends ApiTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        unset($_COOKIE['sbpp_auth']);
    }

    protected function tearDown(): void
    {
        unset($_COOKIE['sbpp_auth']);
        parent::tearDown();
    }

    private function insertSession(string $jti, int $aid): void
    {
        Fixture::rawPdo()->prepare(sprintf(
            'INSERT INTO `%s_login_tokens` (jti, aid, secret, lastAccessed) VALUES (?, ?, ?, UNIX_TIMESTAMP())',
            DB_PREFIX,
        ))->execute([$jti, $aid, Crypto::genSecret()]);
    }

    private function sessionCount(?int $aid = null): int
    {
        $sql = sprintf('SELECT COUNT(*) FROM `%s_login_tokens`', DB_PREFIX);
        if ($aid === null) {
            return (int) Fixture::rawPdo()->query($sql)->fetchColumn();
        }
        $stmt = Fixture::rawPdo()->prepare($sql . ' WHERE aid = ?');
        $stmt->execute([$aid]);
        return (int) $stmt->fetchColumn();
    }

    private function useCookie(string $jti, int $aid, int $maxLife = 3600): void
    {
        $_COOKIE['sbpp_auth'] = JWT::create($jti, $maxLife, $aid)->toString();
    }

    public function testVerifyAcceptsTokenBackedBySessionRow(): void
    {
        $jti = Crypto::genJTI();
        $this->insertSession($jti, Fixture::adminAid());
        $this->useCookie($jti, Fixture::adminAid());

        $this->assertNotNull(\Auth::verify());
    }

    public function testVerifyRejectsTokenWithoutSessionRow(): void
    {
        $this->useCookie(Crypto::genJTI(), Fixture::adminAid());

        $this->assertNull(\Auth::verify());
    }

    public function testVerifyRejectsExpiredToken(): void
    {
        $jti = Crypto::genJTI();
        $this->insertSession($jti, Fixture::adminAid());
        // Expired two minutes ago, beyond the 30s leeway.
        $this->useCookie($jti, Fixture::adminAid(), -120);

        $this->assertNull(\Auth::verify());
    }

    public function testVerifyRejectsSessionRowOwnedByAnotherAdmin(): void
    {
        $jti = Crypto::genJTI();
        $this->insertSession($jti, Fixture::adminAid() + 1000);
        $this->useCookie($jti, Fixture::adminAid());

        $this->assertNull(\Auth::verify());
    }

    public function testVerifyRejectsMalformedCookieWithoutThrowing(): void
    {
        $_COOKIE['sbpp_auth'] = 'not-a-jwt';

        $this->assertNull(\Auth::verify());
    }

    public function testLoginPersistsSessionForTheAdmin(): void
    {
        \Auth::login(Fixture::adminAid(), 3600);

        $this->assertSame(1, $this->sessionCount(Fixture::adminAid()));
    }

    public function testLogoutDeletesTheSessionRow(): void
    {
        $jti = Crypto::genJTI();
        $this->insertSession($jti, Fixture::adminAid());
        $this->useCookie($jti, Fixture::adminAid());

        $this->assertTrue(\Auth::logout());
        $this->assertSame(0, $this->sessionCount(Fixture::adminAid()));
    }

    public function testRevokeAllForAdminOnlyEndsThatAdminsSessions(): void
    {
        $this->insertSession(Crypto::genJTI(), Fixture::adminAid());
        $this->insertSession(Crypto::genJTI(), Fixture::adminAid());
        $this->insertSession(Crypto::genJTI(), Fixture::adminAid() + 1000);

        \Auth::revokeAllForAdmin(Fixture::adminAid());

        $this->assertSame(0, $this->sessionCount(Fixture::adminAid()));
        $this->assertSame(1, $this->sessionCount());
    }

    public function testChangePasswordRevokesEverySessionOfThatAdmin(): void
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf('UPDATE `%s_admins` SET password = ? WHERE aid = ?', DB_PREFIX))
            ->execute([password_hash('old-password-123', PASSWORD_BCRYPT), Fixture::adminAid()]);
        $this->insertSession(Crypto::genJTI(), Fixture::adminAid());
        $this->insertSession(Crypto::genJTI(), Fixture::adminAid());
        $this->loginAsAdmin();

        $this->api('account.change_password', [
            'aid'          => Fixture::adminAid(),
            'old_password' => 'old-password-123',
            'new_password' => 'new-password-456',
        ]);

        $this->assertSame(0, $this->sessionCount(Fixture::adminAid()));
    }

    public function testDeactivatedAdminIsNotLoggedIn(): void
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf('UPDATE `%s_admins` SET enabled = 0 WHERE aid = ?', DB_PREFIX))
            ->execute([Fixture::adminAid()]);

        $this->loginAsAdmin();

        $this->assertFalse($GLOBALS['userbank']->is_logged_in());
    }

    public function testDeletedAdminIsNotLoggedIn(): void
    {
        $this->loginAs(Fixture::adminAid() + 1000);

        $this->assertFalse($GLOBALS['userbank']->is_logged_in());
    }
}
