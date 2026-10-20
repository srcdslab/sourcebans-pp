<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * #57: the ban / comm list GET-fallback key is CSPRNG-minted and checked
 * with hash_equals, failing closed when the session has no key.
 */
final class ListActionKeyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        unset($_SESSION['banlist_postkey']);
    }

    protected function tearDown(): void
    {
        unset($_SESSION['banlist_postkey']);
        parent::tearDown();
    }

    public function testMintsA256BitHexKeyOnce(): void
    {
        $key = sbpp_list_action_key();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
        $this->assertSame($key, sbpp_list_action_key());
        $this->assertSame($key, $_SESSION['banlist_postkey']);
    }

    public function testRotatesLegacyMd5Key(): void
    {
        $_SESSION['banlist_postkey'] = md5('legacy');

        $this->assertNotSame(md5('legacy'), sbpp_list_action_key());
    }

    public function testAcceptsTheSessionKey(): void
    {
        $this->assertTrue(sbpp_list_action_key_valid(sbpp_list_action_key()));
    }

    /** @return array<string, array{mixed}> */
    public static function badCandidateProvider(): array
    {
        return [
            'missing'      => [null],
            'empty'        => [''],
            'array'        => [['x']],
            'wrong'        => [str_repeat('0', 64)],
            'numeric-like' => ['0'],
        ];
    }

    #[DataProvider('badCandidateProvider')]
    public function testRejectsBadCandidates(mixed $candidate): void
    {
        sbpp_list_action_key();

        $this->assertFalse(sbpp_list_action_key_valid($candidate));
    }

    public function testFailsClosedWithoutASessionKey(): void
    {
        // Pre-#57 `'' != null` was false, so `key=` passed on a fresh session.
        $this->assertFalse(sbpp_list_action_key_valid(''));
        $this->assertFalse(sbpp_list_action_key_valid(null));
    }
}
