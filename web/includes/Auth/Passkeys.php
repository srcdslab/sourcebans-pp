<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

use Cose\Algorithm\Manager as AlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use Sbpp\Db\Database;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Passkeys (WebAuthn, #108), on top of web-auth/webauthn-lib.
 *
 * - A passkey signs in on its own (discoverable credential, user
 *   verification required: PIN or biometrics), and counts as both
 *   factors: it satisfies `auth.2fa.require`.
 * - It can also answer the second step after a password or Steam
 *   sign-in, like a TOTP code.
 *
 * The relying party ID and the only accepted origin come from
 * `SBPP_PANEL_URL` ({@see Host::configuredPanelUrl()}), never from the
 * request: without it, passkeys are off ({@see available()}).
 *
 * Challenges are server-side (`:prefix_webauthn_challenges`, keyed on the
 * SHA-256 of the `sbpp_wa` cookie token), single-use and short-lived. The
 * credential record (public key, counter, user handle, backup flags) is
 * stored as the library's JSON in `:prefix_admin_passkeys`; the user
 * handle is an HMAC of the aid, so it doesn't reveal the admin id.
 */
final class Passkeys
{
    public const CHALLENGE_COOKIE = 'sbpp_wa';
    public const CHALLENGE_TTL = 5 * 60;
    public const TIMEOUT_MS = 120000;
    public const MAX_PER_ADMIN = 10;

    public const PURPOSE_REGISTER = 'register';
    public const PURPOSE_LOGIN = 'login';
    public const PURPOSE_SECOND = 'second';

    private ?SerializerInterface $serializer = null;

    /** Test seam: the panel origin, instead of `SBPP_PANEL_URL` (a process-wide constant). */
    private static ?string $originOverride = null;

    /** @internal tests only */
    public static function overrideOriginForTests(?string $origin): void
    {
        self::$originOverride = $origin;
    }

    public function __construct(private Database $dbs) {}

    /** Passkeys need `SBPP_PANEL_URL`: it fixes the relying party ID and origin. */
    public static function available(): bool
    {
        return self::panelOrigin() !== null;
    }

    /**
     * Whether the updater created the passkey tables (migration 821). Code
     * deployed before the updater ran must not fail on them.
     */
    public function tablesExist(): bool
    {
        try {
            $this->dbs->query('SELECT 1 FROM `:prefix_admin_passkeys` LIMIT 1');
            $this->dbs->single();
            $this->dbs->query('SELECT 1 FROM `:prefix_webauthn_challenges` LIMIT 1');
            $this->dbs->single();
            return true;
        } catch (\PDOException $e) {
            if (self::isMissingTable($e)) {
                return false;
            }
            throw $e;
        }
    }

    /** SQLSTATE 42S02 (ER_NO_SUCH_TABLE): the updater hasn't run yet. */
    public static function isMissingTable(\PDOException $e): bool
    {
        $sqlState = is_array($e->errorInfo) ? (string) ($e->errorInfo[0] ?? '') : '';
        if ($sqlState === '') {
            $sqlState = (string) $e->getCode();
        }
        return $sqlState === '42S02';
    }

    /** `scheme://host[:port]` of `SBPP_PANEL_URL`, or null. */
    public static function panelOrigin(): ?string
    {
        $url = self::$originOverride ?? Host::configuredPanelUrl();
        if ($url === null) {
            return null;
        }
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }
        $origin = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }
        // WebAuthn needs a secure context: https, or http only on localhost.
        if (!str_starts_with($origin, 'https://') && strtolower($parts['host']) !== 'localhost') {
            return null;
        }
        return $origin;
    }

    private static function rpId(): string
    {
        return (string) parse_url((string) self::panelOrigin(), PHP_URL_HOST);
    }

    // -- Registration ---------------------------------------------------

    /**
     * Creation options for a new passkey of `$aid` (browser JSON shape),
     * with the challenge stored for {@see finishRegistration()}.
     *
     * @return array<string, mixed>
     */
    public function registrationOptions(int $aid, string $userName): array
    {
        $exclude = array_map(
            static fn (CredentialRecord $r): PublicKeyCredentialDescriptor => $r->getPublicKeyCredentialDescriptor(),
            $this->records($aid),
        );
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('SourceBans++', self::rpId()),
            PublicKeyCredentialUserEntity::create($userName, self::userHandle($aid), $userName),
            random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::createPk(-7),   // ES256
                PublicKeyCredentialParameters::createPk(-8),   // EdDSA
                PublicKeyCredentialParameters::createPk(-257), // RS256
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $exclude,
            timeout: self::TIMEOUT_MS,
        );
        $json = $this->toJson($options);
        $this->storeChallenge(self::PURPOSE_REGISTER, $aid, $json);
        return json_decode($json, true, 32, JSON_THROW_ON_ERROR);
    }

    /**
     * Check the browser's answer to {@see registrationOptions()} and store
     * the passkey. Returns its row id, or null when it doesn't verify.
     *
     * @param array<string, mixed> $credential browser JSON (`PublicKeyCredential`)
     */
    public function finishRegistration(int $aid, array $credential, string $name, int $now): ?int
    {
        $stored = $this->takeChallenge(self::PURPOSE_REGISTER, $aid);
        if ($stored === null || $this->count($aid) >= self::MAX_PER_ADMIN) {
            return null;
        }
        try {
            /** @var PublicKeyCredentialCreationOptions $options */
            $options = $this->serializer()->deserialize($stored, PublicKeyCredentialCreationOptions::class, 'json');
            $pkc = $this->parseCredential($credential);
            if ($pkc === null || !$pkc->response instanceof AuthenticatorAttestationResponse) {
                return null;
            }
            $record = AuthenticatorAttestationResponseValidator::create($this->ceremonies()->creationCeremony())
                ->check($pkc->response, $options, self::rpId());
        } catch (\Throwable $e) {
            error_log('[sbpp] passkey registration refused: ' . $e->getMessage());
            return null;
        }

        $this->dbs->query(
            'INSERT INTO `:prefix_admin_passkeys` (aid, credential_hash, name, record, created, last_used)'
            . ' VALUES (:aid, :h, :name, :record, :now, NULL)'
        );
        $this->dbs->bindMultiple([
            ':aid'    => $aid,
            ':h'      => hash('sha256', $record->publicKeyCredentialId),
            ':name'   => self::cleanName($name),
            ':record' => $this->toJson($record),
            ':now'    => $now,
        ]);
        try {
            $this->dbs->execute();
        } catch (\PDOException) {
            return null; // Same credential registered twice.
        }
        return (int) $this->dbs->lastInsertId();
    }

    // -- Sign-in --------------------------------------------------------

    /**
     * Request options. `login`: any discoverable passkey of this panel
     * (no account named yet). `second`: only `$aid`'s passkeys, for the
     * second step.
     *
     * @return array<string, mixed>
     */
    public function requestOptions(string $purpose, ?int $aid): array
    {
        $allow = $purpose === self::PURPOSE_SECOND && $aid !== null
            ? array_map(
                static fn (CredentialRecord $r): PublicKeyCredentialDescriptor => $r->getPublicKeyCredentialDescriptor(),
                $this->records($aid),
            )
            : [];
        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            rpId: self::rpId(),
            allowCredentials: $allow,
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: self::TIMEOUT_MS,
        );
        $json = $this->toJson($options);
        $this->storeChallenge($purpose, $aid, $json);
        return json_decode($json, true, 32, JSON_THROW_ON_ERROR);
    }

    /**
     * Check an assertion against the stored challenge of `$purpose`.
     * Returns the admin it signs in, or null. With `$expectedAid` (second
     * step), a passkey of another admin is refused.
     *
     * @param array<string, mixed> $credential browser JSON (`PublicKeyCredential`)
     */
    public function finishAssertion(string $purpose, array $credential, ?int $expectedAid, int $now): ?int
    {
        $stored = $this->takeChallenge($purpose, $expectedAid);
        if ($stored === null) {
            return null;
        }
        try {
            /** @var PublicKeyCredentialRequestOptions $options */
            $options = $this->serializer()->deserialize($stored, PublicKeyCredentialRequestOptions::class, 'json');
            $pkc = $this->parseCredential($credential);
            if ($pkc === null || !$pkc->response instanceof AuthenticatorAssertionResponse) {
                return null;
            }
            $row = $this->rowByCredentialId($pkc->rawId);
            if ($row === null || ($expectedAid !== null && $row['aid'] !== $expectedAid)) {
                return null;
            }
            /** @var CredentialRecord $record */
            $record = $this->serializer()->deserialize($row['record'], CredentialRecord::class, 'json');
            $updated = AuthenticatorAssertionResponseValidator::create($this->ceremonies()->requestCeremony())
                ->check($record, $pkc->response, $options, self::rpId(), $pkc->response->userHandle);
        } catch (\Throwable $e) {
            // Includes a signature counter that went backwards (cloned
            // authenticator): the library refuses it.
            error_log('[sbpp] passkey assertion refused: ' . $e->getMessage());
            return null;
        }

        $this->dbs->query('UPDATE `:prefix_admin_passkeys` SET record = :record, last_used = :now WHERE id = :id');
        $this->dbs->bindMultiple([':record' => $this->toJson($updated), ':now' => $now, ':id' => $row['id']]);
        $this->dbs->execute();
        return $row['aid'];
    }

    // -- Management -----------------------------------------------------

    /**
     * Passkeys `$aid` can use right now: none while passkeys are off
     * ({@see available()}) or before the updater created their table.
     * This, not {@see count()}, decides whether a passkey counts as a
     * second factor: a passkey that can't be offered must not open a step
     * the admin can't answer.
     */
    public function usableCount(int $aid): int
    {
        if (!self::available()) {
            return 0;
        }
        try {
            return $this->count($aid);
        } catch (\PDOException $e) {
            if (self::isMissingTable($e)) {
                return 0;
            }
            throw $e;
        }
    }

    public function count(int $aid): int
    {
        $this->dbs->query('SELECT COUNT(*) AS c FROM `:prefix_admin_passkeys` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $row = $this->dbs->single();
        return is_array($row) ? (int) $row['c'] : 0;
    }

    /** @return list<array{id: int, name: string, created: int, last_used: int|null}> */
    public function listFor(int $aid): array
    {
        $this->dbs->query('SELECT id, name, created, last_used FROM `:prefix_admin_passkeys` WHERE aid = :aid ORDER BY created');
        $this->dbs->bind(':aid', $aid);
        $out = [];
        foreach ($this->dbs->resultset() as $row) {
            $out[] = [
                'id'        => (int) $row['id'],
                'name'      => (string) $row['name'],
                'created'   => (int) $row['created'],
                'last_used' => $row['last_used'] === null ? null : (int) $row['last_used'],
            ];
        }
        return $out;
    }

    /** Remove one of `$aid`'s passkeys. False when it isn't theirs. */
    public function remove(int $aid, int $id): bool
    {
        $this->dbs->query('DELETE FROM `:prefix_admin_passkeys` WHERE id = :id AND aid = :aid');
        $this->dbs->bindMultiple([':id' => $id, ':aid' => $aid]);
        $this->dbs->execute();
        return $this->dbs->rowCount() === 1;
    }

    public function removeAll(int $aid): void
    {
        $this->dbs->query('DELETE FROM `:prefix_admin_passkeys` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $this->dbs->execute();
    }

    public static function cleanName(string $name): string
    {
        $name = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name));
        $name = mb_substr($name, 0, 64);
        return $name === '' ? 'Passkey' : $name;
    }

    // -- Internals ------------------------------------------------------

    /**
     * WebAuthn user handle of an admin: an HMAC of the aid (32 bytes), so
     * the authenticator never stores the database id.
     */
    private static function userHandle(int $aid): string
    {
        $secret = JWT::signingKeyFromSecret(SB_SECRET_KEY)->contents();
        return hash_hmac('sha256', 'aid:' . $aid, hash_hkdf('sha256', $secret, 32, 'sbpp-webauthn-user-v1'), true);
    }

    /** @return list<CredentialRecord> */
    private function records(int $aid): array
    {
        $this->dbs->query('SELECT record FROM `:prefix_admin_passkeys` WHERE aid = :aid');
        $this->dbs->bind(':aid', $aid);
        $out = [];
        foreach ($this->dbs->resultset() as $row) {
            try {
                /** @var CredentialRecord $record */
                $record = $this->serializer()->deserialize((string) $row['record'], CredentialRecord::class, 'json');
                $out[] = $record;
            } catch (\Throwable) {
                // An unreadable row can't sign in; skip it.
            }
        }
        return $out;
    }

    /** @return array{id: int, aid: int, record: string}|null */
    private function rowByCredentialId(string $rawId): ?array
    {
        $this->dbs->query('SELECT id, aid, record FROM `:prefix_admin_passkeys` WHERE credential_hash = :h');
        $this->dbs->bind(':h', hash('sha256', $rawId));
        $row = $this->dbs->single();
        if (!is_array($row)) {
            return null;
        }
        return ['id' => (int) $row['id'], 'aid' => (int) $row['aid'], 'record' => (string) $row['record']];
    }

    /** @param array<string, mixed> $credential */
    private function parseCredential(array $credential): ?PublicKeyCredential
    {
        $json = json_encode($credential, JSON_THROW_ON_ERROR);
        if (strlen($json) > 64 * 1024) {
            return null;
        }
        /** @var PublicKeyCredential $pkc */
        $pkc = $this->serializer()->deserialize($json, PublicKeyCredential::class, 'json');
        return $pkc;
    }

    private function storeChallenge(string $purpose, ?int $aid, string $optionsJson): void
    {
        $now = time();
        $this->dbs->query('DELETE FROM `:prefix_webauthn_challenges` WHERE expires <= :now LIMIT 100');
        $this->dbs->bind(':now', $now);
        $this->dbs->execute();

        // One challenge per browser: a new one replaces the previous.
        $old = $_COOKIE[self::CHALLENGE_COOKIE] ?? null;
        if (is_string($old) && $old !== '') {
            $this->dbs->query('DELETE FROM `:prefix_webauthn_challenges` WHERE token_hash = :h');
            $this->dbs->bind(':h', hash('sha256', $old));
            $this->dbs->execute();
        }

        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->dbs->query(
            'INSERT INTO `:prefix_webauthn_challenges` (token_hash, purpose, aid, options, expires)'
            . ' VALUES (:h, :purpose, :aid, :options, :expires)'
        );
        $this->dbs->bindMultiple([
            ':h'       => hash('sha256', $token),
            ':purpose' => $purpose,
            ':aid'     => $aid ?? 0,
            ':options' => $optionsJson,
            ':expires' => $now + self::CHALLENGE_TTL,
        ]);
        $this->dbs->execute();

        $_COOKIE[self::CHALLENGE_COOKIE] = $token;
        if (!headers_sent()) {
            setcookie(self::CHALLENGE_COOKIE, $token, [
                'expires'  => $now + self::CHALLENGE_TTL,
                'path'     => '/',
                'domain'   => Host::cookieDomain(),
                'secure'   => Host::isSecure(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
        }
    }

    /**
     * Consume this browser's challenge of `$purpose` (and `$aid`): it is
     * deleted whatever happens next, so it can't be replayed. Returns the
     * stored options JSON, or null.
     */
    private function takeChallenge(string $purpose, ?int $aid): ?string
    {
        $token = $_COOKIE[self::CHALLENGE_COOKIE] ?? null;
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $token)) {
            return null;
        }
        $hash = hash('sha256', $token);
        $this->dbs->query(
            'SELECT purpose, aid, options, expires FROM `:prefix_webauthn_challenges` WHERE token_hash = :h'
        );
        $this->dbs->bind(':h', $hash);
        $row = $this->dbs->single();

        $this->dbs->query('DELETE FROM `:prefix_webauthn_challenges` WHERE token_hash = :h');
        $this->dbs->bind(':h', $hash);
        $this->dbs->execute();
        $consumed = $this->dbs->rowCount() === 1;
        unset($_COOKIE[self::CHALLENGE_COOKIE]);

        if (!$consumed || !is_array($row) || (int) $row['expires'] <= time() || $row['purpose'] !== $purpose) {
            return null;
        }
        if ((int) $row['aid'] !== ($aid ?? 0)) {
            return null;
        }
        return (string) $row['options'];
    }

    private function ceremonies(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins([(string) self::panelOrigin()]);
        if (self::rpId() === 'localhost') {
            // Lets http://localhost through for development / tests. Still
            // the only way to allow plain http for one RP ID in 5.3: the
            // allowed-origins check reads this list.
            // @phpstan-ignore method.deprecated
            $factory->setSecuredRelyingPartyId(['localhost']);
        }
        $factory->setAlgorithmManager(self::algorithms());
        $factory->setAttestationStatementSupportManager(self::attestationSupport());
        return $factory;
    }

    private static function algorithms(): AlgorithmManager
    {
        return AlgorithmManager::create()->add(ES256::create(), Ed25519::create(), RS256::create());
    }

    private static function attestationSupport(): AttestationStatementSupportManager
    {
        // Attestation is requested as `none`; the others are accepted so an
        // authenticator that still sends one doesn't fail, but no trust
        // anchor is checked (any authenticator may be used).
        return new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
            new FidoU2FAttestationStatementSupport(),
            new PackedAttestationStatementSupport(self::algorithms()),
        ]);
    }

    private function serializer(): SerializerInterface
    {
        return $this->serializer ??= (new WebauthnSerializerFactory(self::attestationSupport()))->create();
    }

    private function toJson(object $value): string
    {
        return $this->serializer()->serialize($value, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        ]);
    }
}
