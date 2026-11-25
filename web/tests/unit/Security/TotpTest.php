<?php

declare(strict_types=1);

namespace Sbpp\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sbpp\Security\Totp;

/** #107: TOTP against the RFC 6238 test vectors (SHA-1, last 6 digits). */
final class TotpTest extends TestCase
{
    /** RFC 6238 appendix B seed: ASCII "12345678901234567890". */
    private static function rfcSecret(): string
    {
        return Totp::base32Encode('12345678901234567890');
    }

    /** @return iterable<string, array{0: int, 1: string}> */
    public static function rfcVectors(): iterable
    {
        // The RFC lists 8-digit codes; a 6-digit code is the same value mod 10^6.
        yield 'T=59'         => [59, '287082'];
        yield 'T=1111111109' => [1111111109, '081804'];
        yield 'T=1111111111' => [1111111111, '050471'];
        yield 'T=1234567890' => [1234567890, '005924'];
        yield 'T=2000000000' => [2000000000, '279037'];
        yield 'T=20000000000' => [20000000000, '353130'];
    }

    #[DataProvider('rfcVectors')]
    public function testRfc6238Vectors(int $time, string $expected): void
    {
        $this->assertSame($expected, Totp::code(self::rfcSecret(), Totp::step($time)));
    }

    public function testBase32RoundTripAndGeneratedSecretShape(): void
    {
        $this->assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', self::rfcSecret());
        $this->assertSame('12345678901234567890', Totp::base32Decode('gezd gnbv gy3t qojq gezd gnbv gy3t qojq'));
        $this->assertNull(Totp::base32Decode('not base32!'));
        $this->assertNull(Totp::base32Decode(''));

        $secret = Totp::generateSecret();
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{32}$/D', $secret);
        $this->assertSame(Totp::SECRET_BYTES, strlen((string) Totp::base32Decode($secret)));
        $this->assertNotSame($secret, Totp::generateSecret());
    }

    public function testMatchStepAcceptsOneStepOfDriftEitherSide(): void
    {
        $secret = self::rfcSecret();
        $now = 1234567890;
        $step = Totp::step($now);

        $this->assertSame($step, Totp::matchStep($secret, Totp::code($secret, $step), $now));
        $this->assertSame($step - 1, Totp::matchStep($secret, Totp::code($secret, $step - 1), $now));
        $this->assertSame($step + 1, Totp::matchStep($secret, Totp::code($secret, $step + 1), $now));
        $this->assertNull(Totp::matchStep($secret, Totp::code($secret, $step - 2), $now));
        $this->assertNull(Totp::matchStep($secret, Totp::code($secret, $step + 2), $now));
    }

    public function testMatchStepSkipsStepsAlreadyUsed(): void
    {
        $secret = self::rfcSecret();
        $now = 1234567890;
        $step = Totp::step($now);
        $code = Totp::code($secret, $step);

        $this->assertNull(Totp::matchStep($secret, $code, $now, $step), 'A used step is refused (replay).');
        $this->assertSame($step, Totp::matchStep($secret, $code, $now, $step - 1));
    }

    public function testCodeFormatting(): void
    {
        $this->assertSame('123456', Totp::normalizeCode(' 123 456 '));
        $this->assertSame('123456', Totp::normalizeCode('123-456'));
        $this->assertNull(Totp::normalizeCode('12345'));
        $this->assertNull(Totp::normalizeCode('1234567'));
        $this->assertNull(Totp::normalizeCode('12345a'));
        $this->assertNull(Totp::matchStep(self::rfcSecret(), 'abcdef', 59));
    }

    public function testProvisioningUri(): void
    {
        $uri = Totp::provisioningUri('SourceBans++ (bans.example.com)', 'ad min', 'ABCDEFGH');
        $this->assertStringStartsWith('otpauth://totp/SourceBans%2B%2B%20%28bans.example.com%29:ad%20min?', $uri);
        $this->assertStringContainsString('secret=ABCDEFGH', $uri);
        $this->assertStringContainsString('digits=6', $uri);
        $this->assertStringContainsString('period=30', $uri);
    }
}
