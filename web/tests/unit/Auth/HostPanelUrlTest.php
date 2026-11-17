<?php

declare(strict_types=1);

namespace Sbpp\Tests\Unit\Auth;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Sbpp\Auth\Host;

/**
 * #71: emailed links (password reset, ban added, contact, SMTP test)
 * were built with `Host::complete(true)`, which drops the install
 * subfolder, so they 404'd on subfolder installs. `Host::panelUrl()`
 * keeps the subfolder and never ends with a slash, so callers can
 * append `/index.php?...` safely.
 *
 * #95: the fallback takes the host name from the client's `Host` header.
 * `SBPP_PANEL_URL` wins when it is set. The constant is process-global,
 * so the tests that define it run in a separate process.
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
     * @return iterable<string, array{string, ?string}>
     */
    public static function panelUrlValues(): iterable
    {
        yield 'root' => ['https://bans.example.com', 'https://bans.example.com'];
        yield 'trailing slash' => ['https://bans.example.com/', 'https://bans.example.com'];
        yield 'subfolder' => ['https://example.com/games/sb/', 'https://example.com/games/sb'];
        yield 'port + http' => ['http://10.0.0.5:8080/sb', 'http://10.0.0.5:8080/sb'];
        yield 'surrounding spaces' => ['  https://example.com  ', 'https://example.com'];
        yield 'empty' => ['', null];
        yield 'no scheme' => ['bans.example.com', null];
        yield 'other scheme' => ['javascript://example.com', null];
        yield 'credentials' => ['https://user:pass@example.com', null];
        yield 'query' => ['https://example.com/?p=login', null];
        yield 'fragment' => ['https://example.com/#x', null];
        yield 'quote' => ['https://example.com/"onmouseover=x', null];
        yield 'angle bracket' => ['https://example.com/<b>', null];
        yield 'newline' => ["https://example.com/\nBcc: x@y", null];
        yield 'empty path segment' => ['https://example.com//sb', null];
    }

    #[DataProvider('panelUrlValues')]
    public function testNormalizePanelUrl(string $value, ?string $expected): void
    {
        $this->assertSame($expected, Host::normalizePanelUrl($value));
    }

    #[RunInSeparateProcess]
    public function testConfiguredPanelUrlWinsOverHostHeader(): void
    {
        define('SBPP_PANEL_URL', 'https://bans.example.com/sb/');
        $_SERVER['HTTP_HOST'] = 'evil.example';
        $_SERVER['REQUEST_URI'] = '/api.php';

        $this->assertSame('https://bans.example.com/sb', Host::panelUrl());
    }

    #[RunInSeparateProcess]
    public function testInvalidConfiguredPanelUrlFallsBackToTheRequest(): void
    {
        define('SBPP_PANEL_URL', 'bans.example.com');
        $_SERVER['REQUEST_URI'] = '/sb/api.php';

        $this->assertNull(Host::configuredPanelUrl());
        $this->assertSame('http://example.com/sb', Host::panelUrl());
    }

    #[RunInSeparateProcess]
    public function testEmptyConfiguredPanelUrlFallsBackToTheRequest(): void
    {
        define('SBPP_PANEL_URL', '');
        $_SERVER['REQUEST_URI'] = '/index.php';

        $this->assertSame('http://example.com', Host::panelUrl());
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
