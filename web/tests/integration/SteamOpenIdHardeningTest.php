<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/Auth/openid.php';

/**
 * Security audit 2026-11: the Steam OpenID callback forwarded every
 * attacker-listed `openid.signed` field to Steam's check_authentication
 * and accepted the reply on an unanchored `/is_valid\s*:\s*true/i` match.
 * A value echoed back by the provider (e.g. `invalidate_handle`) could
 * then log anyone in as any admin. The cURL path also skipped TLS
 * verification, and `?p=login&o=steam` ignored `config.enablesteamlogin`.
 */
final class SteamOpenIdHardeningTest extends TestCase
{
    private const WEB = __DIR__ . '/../../';

    /** @return array<string, string> */
    private static function steamCallback(): array
    {
        $id = 'https://steamcommunity.com/openid/id/76561197960287930';
        return [
            'openid_ns'             => 'http://specs.openid.net/auth/2.0',
            'openid_mode'           => 'id_res',
            'openid_op_endpoint'    => 'https://steamcommunity.com/openid/login',
            'openid_claimed_id'     => $id,
            'openid_identity'       => $id,
            'openid_return_to'      => 'https://panel.example.test/index.php?p=login&o=steam',
            'openid_response_nonce' => '2026-11-08T10:00:00Zabc',
            'openid_assoc_handle'   => '1234567890',
            'openid_signed'         => 'signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle',
            'openid_sig'            => 'c2lnbmF0dXJl',
        ];
    }

    public function testGenuineSteamCallbackShapeIsAccepted(): void
    {
        $this->assertTrue(\LightOpenID::isAcceptedSteamAssertion(self::steamCallback()));
    }

    public function testExtraSignedFieldIsRejected(): void
    {
        $data = self::steamCallback();
        $data['openid_signed'] .= ',invalidate_handle';
        $data['openid_invalidate_handle'] = 'is_valid:true';
        $this->assertFalse(\LightOpenID::isAcceptedSteamAssertion($data));
    }

    public function testMissingSignedFieldIsRejected(): void
    {
        $data = self::steamCallback();
        $data['openid_signed'] = 'signed,op_endpoint,return_to,response_nonce,assoc_handle';
        $this->assertFalse(\LightOpenID::isAcceptedSteamAssertion($data));
    }

    public function testForeignOpEndpointIsRejected(): void
    {
        $data = self::steamCallback();
        $data['openid_op_endpoint'] = 'https://evil.example/openid/login';
        $this->assertFalse(\LightOpenID::isAcceptedSteamAssertion($data));
    }

    public function testClaimedIdMustMatchIdentity(): void
    {
        $data = self::steamCallback();
        $data['openid_identity'] = 'https://steamcommunity.com/openid/id/76561197960287931';
        $this->assertFalse(\LightOpenID::isAcceptedSteamAssertion($data));
    }

    /** @return array<string, array{string, bool}> */
    public static function responses(): array
    {
        return [
            'valid'                  => ["ns:http://specs.openid.net/auth/2.0\nis_valid:true\n", true],
            'invalid'                => ["ns:http://specs.openid.net/auth/2.0\nis_valid:false\n", false],
            'echoed value'           => ["invalidate_handle:is_valid:true\nis_valid:false\n", false],
            'echoed only'            => ["invalidate_handle:is_valid:true\n", false],
            'duplicate is_valid'     => ["is_valid:true\nis_valid:false\n", false],
            'case or spaces'         => ["is_valid: TRUE\n", false],
            'empty'                  => ['', false],
        ];
    }

    #[DataProvider('responses')]
    public function testResponseParsingIsStrict(string $response, bool $expected): void
    {
        $this->assertSame($expected, \LightOpenID::responseIsValid($response));
    }

    public function testCurlPathVerifiesTls(): void
    {
        $src = (string) file_get_contents(self::WEB . 'includes/Auth/openid.php');
        $this->assertStringNotContainsString('CURLOPT_SSL_VERIFYPEER, false', $src);
        $this->assertStringContainsString('CURLOPT_SSL_VERIFYPEER, true', $src);
    }

    public function testSteamLoginRouteHonoursTheSetting(): void
    {
        $src = php_strip_whitespace(self::WEB . 'includes/page-builder.php');
        $gate = strpos($src, "Config::getBool('config.enablesteamlogin')");
        $handler = strpos($src, 'new SteamAuthHandler(');
        $this->assertNotFalse($gate);
        $this->assertNotFalse($handler);
        $this->assertLessThan($handler, $gate);
    }
}
