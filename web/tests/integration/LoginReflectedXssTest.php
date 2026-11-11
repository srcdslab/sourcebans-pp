<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sbpp\Auth\Host;

/**
 * Security audit 2026-11: `/index.php/x');alert(1);('?p=login&m=failed`
 * reflected the request path into a JS string literal on the login page.
 *
 * Pins both halves of the fix: the login handler no longer echoes
 * `Host::complete()` into a script, and `Host::complete()` drops any path
 * segment that carries quote / paren / `;` / `&` / angle-bracket bytes.
 */
final class LoginReflectedXssTest extends TestCase
{
    private const WEB = __DIR__ . '/../../';

    /** @var array<string, mixed> */
    private array $server;

    protected function setUp(): void
    {
        $this->server = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'panel.example.test';
        unset($_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO']);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
    }

    /** @return array<string, array{string}> */
    public static function hostilePaths(): array
    {
        return [
            'js string breakout' => ["/index.php/x');alert(document.domain);('"],
            'double quote'       => ['/x"onmouseover="alert(1)/index.php'],
            'angle brackets'     => ['/<svg>/index.php'],
            'rcon separator'     => ['/api.php/x;quit'],
            'ampersand'          => ['/a&b/index.php'],
        ];
    }

    #[DataProvider('hostilePaths')]
    public function testCompleteDropsHostileSegments(string $uri): void
    {
        $_SERVER['REQUEST_URI'] = $uri . '?p=login&m=failed';
        $url = Host::complete();
        foreach (["'", '"', '(', ')', ';', '<', '>', '&'] as $char) {
            $this->assertStringNotContainsString($char, $url, "Host::complete() kept `$char` from $uri");
        }
    }

    public function testCompleteKeepsASubfolderInstall(): void
    {
        $_SERVER['REQUEST_URI'] = '/sourcebans/index.php?p=login';
        $this->assertStringEndsWith('panel.example.test/sourcebans', Host::complete());
    }

    public function testLoginHandlerNoLongerEchoesTheRequestUrlIntoAScript(): void
    {
        $src = php_strip_whitespace(self::WEB . 'pages/page.login.php');
        $this->assertStringNotContainsString('Host::complete()', $src);
        $this->assertStringNotContainsString('ShowBox', $src);
    }
}
