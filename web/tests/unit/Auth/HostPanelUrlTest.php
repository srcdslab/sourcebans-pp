<?php

declare(strict_types=1);

namespace Sbpp\Tests\Unit\Auth;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sbpp\Auth\Host;

/**
 * #71: emailed links (password reset, ban added, contact, SMTP test)
 * were built with `Host::complete(true)`, which drops the install
 * subfolder, so they 404'd on subfolder installs. `Host::panelUrl()`
 * keeps the subfolder and never ends with a slash, so callers can
 * append `/index.php?...` safely.
 */
final class HostPanelUrlTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $server;

    protected function setUp(): void
    {
        parent::setUp();
        $this->server = $_SERVER;
        unset($_SERVER['HTTPS'], $_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['REMOTE_ADDR']);
        $_SERVER['HTTP_HOST'] = 'example.com';
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
        parent::tearDown();
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function requestUris(): iterable
    {
        yield 'root index.php' => ['/index.php?p=lostpassword', 'http://example.com'];
        yield 'root api.php' => ['/api.php', 'http://example.com'];
        yield 'root bare' => ['/', 'http://example.com'];
        yield 'subfolder index.php' => ['/sb/index.php?p=lostpassword&email=a', 'http://example.com/sb'];
        yield 'subfolder api.php' => ['/sb/api.php', 'http://example.com/sb'];
        yield 'subfolder bare' => ['/sb/', 'http://example.com/sb'];
        yield 'nested subfolder' => ['/games/sb/api.php', 'http://example.com/games/sb'];
    }

    #[DataProvider('requestUris')]
    public function testPanelUrlKeepsSubfolderWithoutTrailingSlash(string $uri, string $expected): void
    {
        $_SERVER['REQUEST_URI'] = $uri;

        $this->assertSame($expected, Host::panelUrl());
    }

    public function testPanelUrlUsesHttpsWhenSecure(): void
    {
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['REQUEST_URI'] = '/sb/api.php';

        $this->assertSame('https://example.com/sb', Host::panelUrl());
    }

    /**
     * `complete(true)` is the shape that caused #71. Every emailed link
     * goes through `panelUrl()` instead.
     */
    public function testNoCallSiteUsesCompleteWithoutRequest(): void
    {
        $root = dirname(__DIR__, 3);
        $offenders = [];
        foreach (['api', 'pages', 'includes'] as $dir) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/' . $dir, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                $path = str_replace('\\', '/', (string) $file);
                if (!str_ends_with($path, '.php') || str_contains($path, '/vendor/')) {
                    continue;
                }
                if (preg_match('/Host::complete\(\s*true\s*\)/', (string) php_strip_whitespace($path))) {
                    $offenders[] = substr($path, strlen($root) + 1);
                }
            }
        }

        $this->assertSame([], $offenders, 'Use Host::panelUrl() for emailed links (#71).');
    }
}
