<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

namespace Sbpp\Tests\Api;

use Sbpp\Auth\Passkeys;
use Sbpp\Auth\TwoFactor;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;

/**
 * #108: passkeys, driven through the real ceremonies with a software
 * authenticator (P-256 key, `none` attestation) defined below.
 */
final class PasskeysTest extends ApiTestCase
{
    private const ORIGIN = 'https://bans.example.test';

    protected function setUp(): void
    {
        parent::setUp();
        Passkeys::overrideOriginForTests(self::ORIGIN);
        Fixture::rawPdo()->exec('DELETE FROM `' . DB_PREFIX . '_login_tokens`');
    }

    protected function tearDown(): void
    {
        Passkeys::overrideOriginForTests(null);
        unset($_COOKIE[TwoFactor::PENDING_COOKIE], $_COOKIE[Passkeys::CHALLENGE_COOKIE]);
        parent::tearDown();
    }

    // -- Availability ---------------------------------------------------

    public function testOffWithoutAPanelUrlOrOverPlainHttp(): void
    {
        Passkeys::overrideOriginForTests(null);
        $this->assertFalse(Passkeys::available(), 'No SBPP_PANEL_URL in the test run.');
        $this->loginAsAdmin();
        $this->assertSame('unavailable', $this->api('account.passkey_register_start', ['password' => 'admin'])['error']['code'] ?? null);
        $this->assertSame('unavailable', $this->api('auth.passkey_login_start', [])['error']['code'] ?? null);

        Passkeys::overrideOriginForTests('http://bans.example.test');
        $this->assertFalse(Passkeys::available(), 'WebAuthn needs https outside localhost.');
        Passkeys::overrideOriginForTests('http://localhost:8080');
        $this->assertSame('http://localhost:8080', Passkeys::panelOrigin());
    }

    // -- Registration ---------------------------------------------------

    public function testRegisterAPasskeyFromYourAccount(): void
    {
        $this->loginAsAdmin();
        $this->assertSame('bad_password', $this->api('account.passkey_register_start', ['password' => 'x'])['error']['code'] ?? null);

        $start = $this->api('account.passkey_register_start', ['password' => 'admin']);
        $this->assertTrue($start['ok'] ?? false, json_encode($start));
        $options = $start['data']['options'];
        $this->assertSame('bans.example.test', $options['rp']['id']);
        $this->assertSame('required', $options['authenticatorSelection']['userVerification']);
        $this->assertSame('required', $options['authenticatorSelection']['residentKey']);
        $this->assertNotSame((string) Fixture::adminAid(), SoftAuthenticator::fromB64url($options['user']['id']), 'The user handle is not the aid.');

        $key = new SoftAuthenticator();
        $done = $this->api('account.passkey_register_finish', ['credential' => $key->register($options, self::ORIGIN), 'name' => " Laptop\x07 "]);

        $this->assertTrue($done['ok'] ?? false, json_encode($done));
        $this->assertCount(TwoFactor::RECOVERY_CODES, $done['data']['recovery_codes'], 'First second factor: recovery codes.');
        $list = (new Passkeys($GLOBALS['PDO']))->listFor(Fixture::adminAid());
        $this->assertCount(1, $list);
        $this->assertSame('Laptop', $list[0]['name']);
        $this->assertTrue((new TwoFactor($GLOBALS['PDO']))->hasSecondFactor(Fixture::adminAid()));
        $this->assertSame(1, $this->logCount('Passkey added'));
    }

    public function testRegistrationFromAnotherOriginOrReplayedIsRefused(): void
    {
        $this->loginAsAdmin();
        $key = new SoftAuthenticator();

        $options = $this->api('account.passkey_register_start', ['password' => 'admin'])['data']['options'];
        $phished = $this->api('account.passkey_register_finish', ['credential' => $key->register($options, 'https://evil.example')]);
        $this->assertSame('invalid_passkey', $phished['error']['code'] ?? null);

        $options = $this->api('account.passkey_register_start', ['password' => 'admin'])['data']['options'];
        $credential = $key->register($options, self::ORIGIN);
        $this->assertTrue($this->api('account.passkey_register_finish', ['credential' => $credential])['ok'] ?? false);
        $replay = $this->api('account.passkey_register_finish', ['credential' => $credential]);
        $this->assertSame('invalid_passkey', $replay['error']['code'] ?? null, 'A challenge is used once.');
    }

    public function testRegistrationWithoutUserVerificationIsRefused(): void
    {
        $this->loginAsAdmin();
        $options = $this->api('account.passkey_register_start', ['password' => 'admin'])['data']['options'];
        $key = new SoftAuthenticator(userVerified: false);

        $env = $this->api('account.passkey_register_finish', ['credential' => $key->register($options, self::ORIGIN)]);

        $this->assertSame('invalid_passkey', $env['error']['code'] ?? null);
    }

    // -- Passwordless sign-in -------------------------------------------

    public function testPasswordlessSignInStartsASession(): void
    {
        $key = $this->registerFor(Fixture::adminAid());

        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $this->assertSame([], $options['allowCredentials'] ?? [], 'No account is named before the passkey answers.');
        $env = $this->api('auth.passkey_login_finish', ['credential' => $key->assert($options, self::ORIGIN, 1)]);

        $this->assertSame('?', $env['redirect'] ?? null);
        $this->assertSame(1, $this->sessions());
    }

    public function testPasswordlessSignInSatisfiesTheRequirement(): void
    {
        $key = $this->registerFor(Fixture::adminAid());
        $this->setRequirement(TwoFactor::REQUIRE_ALL);

        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $env = $this->api('auth.passkey_login_finish', ['credential' => $key->assert($options, self::ORIGIN, 1)]);

        $this->assertSame('?', $env['redirect'] ?? null, 'No setup step: a passkey is two factors.');
    }

    public function testForgedReplayedClonedOrForeignAssertionsAreRefused(): void
    {
        $key = $this->registerFor(Fixture::adminAid());

        // Wrong origin (phishing proxy).
        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $this->assertSame('?p=login&m=passkey_failed', $this->api('auth.passkey_login_finish', ['credential' => $key->assert($options, 'https://evil.example', 1)])['redirect'] ?? null);

        // A good assertion, replayed: the challenge is gone.
        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $good = $key->assert($options, self::ORIGIN, 5);
        $this->assertSame('?', $this->api('auth.passkey_login_finish', ['credential' => $good])['redirect'] ?? null);
        $this->assertSame('?p=login&m=passkey_failed', $this->api('auth.passkey_login_finish', ['credential' => $good])['redirect'] ?? null);

        // Signature counter going backwards: a cloned authenticator.
        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $this->assertSame('?p=login&m=passkey_failed', $this->api('auth.passkey_login_finish', ['credential' => $key->assert($options, self::ORIGIN, 3)])['redirect'] ?? null);

        // A key this panel never registered.
        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $stranger = new SoftAuthenticator();
        $this->assertSame('?p=login&m=passkey_failed', $this->api('auth.passkey_login_finish', ['credential' => $stranger->assert($options, self::ORIGIN, 1)])['redirect'] ?? null);

        // Tampered signature.
        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $bad = $key->assert($options, self::ORIGIN, 9, tamper: true);
        $this->assertSame('?p=login&m=passkey_failed', $this->api('auth.passkey_login_finish', ['credential' => $bad])['redirect'] ?? null);

        $this->assertSame(1, $this->sessions(), 'Only the one good assertion signed in.');
    }

    public function testNoUserVerificationOnSignInIsRefused(): void
    {
        $key = $this->registerFor(Fixture::adminAid());
        $key->userVerified = false;

        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $env = $this->api('auth.passkey_login_finish', ['credential' => $key->assert($options, self::ORIGIN, 1)]);

        $this->assertSame('?p=login&m=passkey_failed', $env['redirect'] ?? null);
    }

    public function testDeactivatedAdminCannotSignInWithAPasskey(): void
    {
        $key = $this->registerFor(Fixture::adminAid());
        Fixture::rawPdo()->exec('UPDATE `' . DB_PREFIX . '_admins` SET enabled = 0 WHERE aid = ' . Fixture::adminAid());

        $options = $this->api('auth.passkey_login_start', [])['data']['options'];
        $env = $this->api('auth.passkey_login_finish', ['credential' => $key->assert($options, self::ORIGIN, 1)]);

        $this->assertSame('?p=login&m=passkey_failed', $env['redirect'] ?? null);
        $this->assertSame(0, $this->sessions());
    }

    // -- Second step ----------------------------------------------------

    public function testPasskeyAnswersTheSecondStepAfterAPassword(): void
    {
        $key = $this->registerFor(Fixture::adminAid());

        $login = $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $this->assertSame('?p=login&step=2fa', $login['redirect'] ?? null, 'A passkey is a second factor.');
        $this->assertSame(0, $this->sessions());

        $options = $this->api('auth.2fa_passkey_start', [])['data']['options'];
        $this->assertCount(1, $options['allowCredentials']);
        $env = $this->api('auth.2fa_passkey_finish', ['credential' => $key->assert($options, self::ORIGIN, 1)]);

        $this->assertSame('?', $env['redirect'] ?? null);
        $this->assertSame(1, $this->sessions());
    }

    public function testAnotherAdminsPasskeyCannotAnswerTheSecondStep(): void
    {
        $this->registerFor(Fixture::adminAid());
        $otherAid = $this->seedAdmin('other108');
        $otherKey = $this->registerFor($otherAid);

        $this->api('auth.login', ['username' => 'admin', 'password' => 'admin']);
        $options = $this->api('auth.2fa_passkey_start', [])['data']['options'];
        $env = $this->api('auth.2fa_passkey_finish', ['credential' => $otherKey->assert($options, self::ORIGIN, 1)]);

        $this->assertSame('invalid_passkey', $env['error']['code'] ?? null);
        $this->assertSame(0, $this->sessions());
    }

    // -- Removal / reset ------------------------------------------------

    public function testTheLastFactorCannotBeRemovedWhileRequired(): void
    {
        $this->registerFor(Fixture::adminAid());
        $this->setRequirement(TwoFactor::REQUIRE_OWNERS);
        $this->loginAsAdmin();
        $id = (new Passkeys($GLOBALS['PDO']))->listFor(Fixture::adminAid())[0]['id'];

        $env = $this->api('account.passkey_remove', ['id' => $id, 'password' => 'admin']);
        $this->assertSame('required', $env['error']['code'] ?? null);

        $this->setRequirement(TwoFactor::REQUIRE_OFF);
        $env = $this->api('account.passkey_remove', ['id' => $id, 'password' => 'admin']);
        $this->assertTrue($env['ok'] ?? false, json_encode($env));
        $this->assertSame(0, (new Passkeys($GLOBALS['PDO']))->count(Fixture::adminAid()));
    }

    public function testCannotRemoveAnotherAdminsPasskey(): void
    {
        $otherAid = $this->seedAdmin('other108');
        $this->registerFor($otherAid);
        $id = (new Passkeys($GLOBALS['PDO']))->listFor($otherAid)[0]['id'];
        $this->loginAsAdmin();

        $env = $this->api('account.passkey_remove', ['id' => $id, 'password' => 'admin']);

        $this->assertSame('not_found', $env['error']['code'] ?? null);
        $this->assertSame(1, (new Passkeys($GLOBALS['PDO']))->count($otherAid));
    }

    public function testOwnerResetRemovesPasskeysToo(): void
    {
        $otherAid = $this->seedAdmin('other108');
        $this->registerFor($otherAid);
        $this->loginAsAdmin();

        $this->assertTrue($this->api('admins.2fa_reset', ['aid' => $otherAid])['ok'] ?? false);

        $this->assertSame(0, (new Passkeys($GLOBALS['PDO']))->count($otherAid));
    }

    // -- Helpers --------------------------------------------------------

    /** Register a soft passkey for `$aid` through the service (not the API, which needs a session). */
    private function registerFor(int $aid): SoftAuthenticator
    {
        $passkeys = new Passkeys($GLOBALS['PDO']);
        $options = $passkeys->registrationOptions($aid, 'user' . $aid);
        $key = new SoftAuthenticator();
        $this->assertNotNull($passkeys->finishRegistration($aid, $key->register($options, self::ORIGIN), 'Soft', time()));
        return $key;
    }

    private function seedAdmin(string $user): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(
            'INSERT INTO `' . DB_PREFIX . '_admins` (user, authid, password, gid, email, extraflags, immunity, srv_group, srv_flags, srv_password)'
            . " VALUES (?, '', ?, -1, ?, 0, 0, '', '', '')"
        )->execute([$user, password_hash('pw' . $user, PASSWORD_BCRYPT), $user . '@example.test']);
        return (int) $pdo->lastInsertId();
    }

    private function setRequirement(string $value): void
    {
        Fixture::rawPdo()->prepare('REPLACE INTO `' . DB_PREFIX . '_settings` (setting, value) VALUES (?, ?)')
            ->execute([TwoFactor::SETTING, $value]);
        \Config::init($GLOBALS['PDO']);
    }

    private function sessions(): int
    {
        return (int) Fixture::rawPdo()->query('SELECT COUNT(*) FROM `' . DB_PREFIX . '_login_tokens`')->fetchColumn();
    }

    private function logCount(string $title): int
    {
        $stmt = Fixture::rawPdo()->prepare('SELECT COUNT(*) FROM `' . DB_PREFIX . '_log` WHERE title = ?');
        $stmt->execute([$title]);
        return (int) $stmt->fetchColumn();
    }
}

/**
 * A software WebAuthn authenticator for the tests: one P-256 credential,
 * `none` attestation, a tiny CBOR encoder. Builds what a browser would send
 * back (`PublicKeyCredential` JSON with base64url fields).
 */
final class SoftAuthenticator
{
    private \OpenSSLAsymmetricKey $key;
    private string $credentialId;
    private string $userHandle = '';

    public function __construct(public bool $userVerified = true)
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed');
        }
        $this->key = $key;
        $this->credentialId = random_bytes(16);
    }

    /**
     * @param array<string, mixed> $options creation options JSON
     * @return array<string, mixed>
     */
    public function register(array $options, string $origin): array
    {
        $this->userHandle = self::fromB64url((string) $options['user']['id']);
        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $options['challenge'],
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $details = openssl_pkey_get_details($this->key);
        $cose = self::map([
            [1, 2],                                             // kty: EC2
            [3, -7],                                            // alg: ES256
            [-1, 1],                                            // crv: P-256
            [-2, self::bytes($details['ec']['x'])],
            [-3, self::bytes($details['ec']['y'])],
        ]);
        $authData = hash('sha256', (string) $options['rp']['id'], true)
            . chr(0x41 | ($this->userVerified ? 0x04 : 0))      // UP + AT (+ UV)
            . pack('N', 0)
            . str_repeat("\0", 16)                              // AAGUID
            . pack('n', strlen($this->credentialId)) . $this->credentialId
            . $cose;
        $attestation = self::map([
            [self::text('fmt'), self::text('none')],
            [self::text('attStmt'), self::map([])],
            [self::text('authData'), self::bytes($authData)],
        ]);

        return [
            'id' => self::b64url($this->credentialId),
            'rawId' => self::b64url($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::b64url($clientData),
                'attestationObject' => self::b64url($attestation),
                'transports' => ['internal'],
            ],
            'clientExtensionResults' => [],
        ];
    }

    /**
     * @param array<string, mixed> $options request options JSON
     * @return array<string, mixed>
     */
    public function assert(array $options, string $origin, int $counter, bool $tamper = false): array
    {
        $clientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $options['challenge'],
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authData = hash('sha256', (string) $options['rpId'], true)
            . chr(0x01 | ($this->userVerified ? 0x04 : 0))
            . pack('N', $counter);
        openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);
        if ($tamper) {
            $signature[10] = chr(ord($signature[10]) ^ 1);
        }

        return [
            'id' => self::b64url($this->credentialId),
            'rawId' => self::b64url($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::b64url($clientData),
                'authenticatorData' => self::b64url($authData),
                'signature' => self::b64url($signature),
                'userHandle' => self::b64url($this->userHandle),
            ],
            'clientExtensionResults' => [],
        ];
    }

    public static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function fromB64url(string $text): string
    {
        return (string) base64_decode(strtr($text, '-_', '+/'), true);
    }

    // Minimal CBOR (RFC 8949): ints, byte/text strings, maps.

    private static function head(int $major, int $len): string
    {
        if ($len < 24) {
            return chr(($major << 5) | $len);
        }
        if ($len < 256) {
            return chr(($major << 5) | 24) . chr($len);
        }
        return chr(($major << 5) | 25) . pack('n', $len);
    }

    private static function int(int $v): string
    {
        return $v >= 0 ? self::head(0, $v) : self::head(1, -1 - $v);
    }

    private static function bytes(string $b): string
    {
        return self::head(2, strlen($b)) . $b;
    }

    private static function text(string $t): string
    {
        return self::head(3, strlen($t)) . $t;
    }

    /** @param list<array{0: int|string, 1: int|string}> $pairs encoded keys/values, or ints */
    private static function map(array $pairs): string
    {
        $out = self::head(5, count($pairs));
        foreach ($pairs as [$k, $v]) {
            $out .= (is_int($k) ? self::int($k) : $k) . (is_int($v) ? self::int($v) : $v);
        }
        return $out;
    }
}
