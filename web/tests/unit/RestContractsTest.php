<?php

declare(strict_types=1);

namespace Sbpp\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sbpp\Api\ApiError;
use Sbpp\Rest\Coerce;
use Sbpp\Rest\Envelope;
use Sbpp\Rest\FrontController;
use Sbpp\Rest\Router;

final class RestContractsTest extends TestCase
{
    public function testRouterDoesNotTreatDotAsWildcard(): void
    {
        $router = new Router([
            [
                'method' => 'GET',
                'path' => '/openapi.yaml',
                'auth' => false,
                'perm' => 0,
                'handler' => static fn (): mixed => null,
            ],
        ]);
        $hit = $router->match('GET', '/openapi.yaml');
        $this->assertArrayHasKey('route', $hit);
        $miss = $router->match('GET', '/openapiXyaml');
        $this->assertSame(404, $miss['error'] ?? null);
    }

    public function testCoerceBool(): void
    {
        $this->assertTrue(Coerce::bool(true));
        $this->assertTrue(Coerce::bool(1));
        $this->assertTrue(Coerce::bool('1'));
        $this->assertTrue(Coerce::bool('true'));
        $this->assertFalse(Coerce::bool(false));
        $this->assertFalse(Coerce::bool(0));
        $this->assertFalse(Coerce::bool('0'));
        $this->assertFalse(Coerce::bool('false'));
        $this->assertFalse(Coerce::bool('maybe'));
    }

    public function testCoerceMinutesFromSeconds(): void
    {
        $this->assertSame(0, Coerce::minutesFromSeconds(0));
        $this->assertSame(0, Coerce::minutesFromSeconds(-1));
        $this->assertSame(1, Coerce::minutesFromSeconds(60));
        $this->assertSame(1, Coerce::minutesFromSeconds(119));
        $this->assertSame(60, Coerce::minutesFromSeconds(3600));
    }

    public function testCorsHeadersAlwaysVaryWhenAllowlistSet(): void
    {
        $allowed = FrontController::corsHeadersFor('https://staff.example.com', 'https://staff.example.com');
        $this->assertSame('Origin', $allowed['Vary'] ?? null);
        $this->assertSame('https://staff.example.com', $allowed['Access-Control-Allow-Origin'] ?? null);

        $missing = FrontController::corsHeadersFor('', 'https://staff.example.com');
        $this->assertSame(['Vary' => 'Origin'], $missing);

        $rejected = FrontController::corsHeadersFor('https://evil.example', 'https://staff.example.com');
        $this->assertSame(['Vary' => 'Origin'], $rejected);
        $this->assertArrayNotHasKey('Access-Control-Allow-Origin', $rejected);

        $this->assertSame([], FrontController::corsHeadersFor('https://staff.example.com', ''));
    }

    public function testEnvelopeMapsFailedCodesTo500(): void
    {
        $create = Envelope::fromApiError(new ApiError('create_failed', 'nope'));
        $this->assertSame(500, $create->status);
        $rehash = Envelope::fromApiError(new ApiError('rehash_failed', 'nope'));
        $this->assertSame(500, $rehash->status);
        $archive = Envelope::fromApiError(new ApiError('archive_failed', 'nope'));
        $this->assertSame(500, $archive->status);
        $restore = Envelope::fromApiError(new ApiError('restore_failed', 'nope'));
        $this->assertSame(500, $restore->status);
        $unknownFailed = Envelope::fromApiError(new ApiError('kick_failed', 'nope'));
        $this->assertSame(500, $unknownFailed->status);
        $validation = Envelope::fromApiError(new ApiError('validation', 'nope'));
        $this->assertSame(400, $validation->status);
    }

    public function testRequestPathUrlDecodesPrettyUrls(): void
    {
        $prev = $_SERVER;
        try {
            unset($_SERVER['PATH_INFO']);
            $_SERVER['REQUEST_URI'] = '/api/v1/admins/76561197960265728%2Fextra';
            $this->assertSame('/admins/76561197960265728/extra', FrontController::requestPath());

            $_SERVER['PATH_INFO'] = '/me';
            $this->assertSame('/me', FrontController::requestPath());
        } finally {
            $_SERVER = $prev;
        }
    }
}
