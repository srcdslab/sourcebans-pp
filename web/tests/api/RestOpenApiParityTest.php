<?php

namespace Sbpp\Tests\Api;

use PHPUnit\Framework\TestCase;
use Sbpp\Rest\Routes;

/**
 * OpenAPI paths must match {@see Routes::all()} byte-for-byte on
 * METHOD + path. Parser walks only the `paths:` block so `components:`
 * `$ref` noise cannot invent routes.
 */
final class RestOpenApiParityTest extends TestCase
{
    public function testOpenApiOperationsMatchRoutes(): void
    {
        $raw = (string) file_get_contents(ROOT . 'api/openapi-v1.yaml');
        $this->assertNotSame('', $raw, 'openapi-v1.yaml must be readable');
        $yaml = str_replace("\r\n", "\n", $raw);
        $fromSpec = $this->operationsFromOpenApi($yaml);
        $fromCode = [];
        foreach (Routes::all() as $route) {
            $fromCode[] = $route['method'] . ' ' . $route['path'];
        }
        sort($fromSpec);
        sort($fromCode);
        $this->assertSame(
            $fromCode,
            $fromSpec,
            "OpenAPI paths drifted from Routes::all()\n"
            . 'only in spec: ' . implode(', ', array_diff($fromSpec, $fromCode)) . "\n"
            . 'only in code: ' . implode(', ', array_diff($fromCode, $fromSpec)),
        );
    }

    /**
     * @return list<string>
     */
    private function operationsFromOpenApi(string $yaml): array
    {
        $pathsAt = strpos($yaml, "\npaths:");
        $componentsAt = strpos($yaml, "\ncomponents:");
        $this->assertNotFalse($pathsAt, 'openapi-v1.yaml must contain a paths: block');
        $this->assertNotFalse($componentsAt, 'openapi-v1.yaml must contain a components: block');
        $this->assertGreaterThan($pathsAt, $componentsAt, 'components: must follow paths:');

        $block = substr($yaml, $pathsAt, $componentsAt - $pathsAt);
        $path = null;
        $ops = [];
        foreach (explode("\n", $block) as $line) {
            if (preg_match('#^  (/[^:]+):$#', $line, $m) === 1) {
                $path = $m[1];
                continue;
            }
            if ($path !== null && preg_match('#^    (get|put|post|patch|delete):$#i', $line, $m) === 1) {
                $ops[] = strtoupper($m[1]) . ' ' . $path;
            }
        }
        return $ops;
    }
}
