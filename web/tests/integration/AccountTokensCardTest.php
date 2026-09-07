<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Your Account token card keeps the table and empty copy in the DOM
 * so create/revoke can toggle them without a reload.
 */
final class AccountTokensCardTest extends TestCase
{
    public function testTableAndEmptyStateBothShip(): void
    {
        $src = (string) file_get_contents(ROOT . 'themes/default/page_youraccount.tpl');
        $this->assertStringContainsString('data-testid="account-tokens-table"', $src);
        $this->assertStringContainsString('data-testid="account-tokens-body"', $src);
        $this->assertStringContainsString('data-testid="account-tokens-empty"', $src);
        $this->assertStringContainsString('insertTokenRow', $src);
        $this->assertStringContainsString('syncTokenEmptyState', $src);
        $this->assertStringContainsString('{if !$api_tokens} hidden{/if}', $src);
        $this->assertStringContainsString('{if $api_tokens} hidden{/if}', $src);
    }
}
