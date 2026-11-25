<?php

declare(strict_types=1);

namespace Sbpp\Tests\Unit\Security;

use PHPUnit\Framework\TestCase;
use Sbpp\Security\SecretBox;

/** #107: TOTP secrets are stored sealed, bound to a purpose. */
final class SecretBoxTest extends TestCase
{
    public function testRoundTripAndFreshNonce(): void
    {
        $a = SecretBox::seal('JBSWY3DPEHPK3PXP', 'totp');
        $b = SecretBox::seal('JBSWY3DPEHPK3PXP', 'totp');

        $this->assertNotSame($a, $b, 'Each seal uses a new nonce.');
        $this->assertStringNotContainsString('JBSWY3DPEHPK3PXP', $a);
        $this->assertSame('JBSWY3DPEHPK3PXP', SecretBox::open($a, 'totp'));
    }

    public function testTamperedWrongPurposeAndGarbageAreRefused(): void
    {
        $sealed = SecretBox::seal('secret', 'totp');
        $raw = (string) base64_decode(substr($sealed, 4), true);
        $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1);

        $this->assertNull(SecretBox::open('sb1:' . base64_encode($raw), 'totp'), 'Tampered.');
        $this->assertNull(SecretBox::open($sealed, 'other'), 'Another purpose derives another key.');
        $this->assertNull(SecretBox::open('plain-text', 'totp'));
        $this->assertNull(SecretBox::open('sb1:%%%', 'totp'));
        $this->assertNull(SecretBox::open('sb1:' . base64_encode('short'), 'totp'));
    }
}
