<?php

namespace Sbpp\Tests\Api;

use Sbpp\Tests\Fixture;

final class RestGroupsTest extends RestTestCase
{
    public function testListRequiresToken(): void
    {
        $response = $this->rest('GET', '/groups');
        $this->assertRestError($response, 401, 'unauthorized');
    }

    public function testListReturnsWebAndServerWithTotals(): void
    {
        $this->seedWebGroup('Rest Web Alpha');
        $this->seedWebGroup('Rest Web Beta');
        $this->seedServerGroup('Rest Srv Alpha');
        $token = $this->mintToken();

        $list = $this->rest('GET', '/groups', token: $token);
        $this->assertSame(200, $list->status, json_encode($list->payload));
        $this->assertArrayHasKey('web', $list->payload['data']);
        $this->assertArrayHasKey('server', $list->payload['data']);
        $this->assertGreaterThanOrEqual(2, $list->payload['meta']['web_total']);
        $this->assertGreaterThanOrEqual(1, $list->payload['meta']['server_total']);
        $this->assertSame(1, $list->payload['meta']['page']);
        $this->assertSame(100, $list->payload['meta']['per_page']);
        $webNames = array_column($list->payload['data']['web'], 'name');
        $this->assertContains('Rest Web Alpha', $webNames);
        $this->assertContains('Rest Web Beta', $webNames);
    }

    public function testKindWebOmitsServerRows(): void
    {
        $this->seedWebGroup('Kind Web');
        $this->seedServerGroup('Kind Srv');
        $token = $this->mintToken();

        $list = $this->rest('GET', '/groups', token: $token, query: ['kind' => 'web']);
        $this->assertSame(200, $list->status, json_encode($list->payload));
        $this->assertNotSame([], $list->payload['data']['web']);
        $this->assertSame([], $list->payload['data']['server']);
        $this->assertGreaterThanOrEqual(1, $list->payload['meta']['server_total']);
    }

    public function testPerPageSlicesEachCatalog(): void
    {
        $this->seedWebGroup('Page Web A');
        $this->seedWebGroup('Page Web B');
        $this->seedWebGroup('Page Web C');
        $token = $this->mintToken();

        $list = $this->rest('GET', '/groups', token: $token, query: [
            'kind' => 'web',
            'per_page' => 1,
            'page' => 1,
        ]);
        $this->assertSame(200, $list->status, json_encode($list->payload));
        $this->assertCount(1, $list->payload['data']['web']);
        $this->assertSame([], $list->payload['data']['server']);
        $this->assertSame(1, $list->payload['meta']['per_page']);
        $this->assertGreaterThanOrEqual(3, $list->payload['meta']['web_total']);
    }

    public function testInvalidKindIs400(): void
    {
        $token = $this->mintToken();
        $response = $this->rest('GET', '/groups', token: $token, query: ['kind' => 'discord']);
        $this->assertRestError($response, 400, 'validation');
        $this->assertSame('kind', $response->payload['error']['field'] ?? null);
    }

    public function testPerPageCapsAt100(): void
    {
        $token = $this->mintToken();
        $list = $this->rest('GET', '/groups', token: $token, query: ['per_page' => 500]);
        $this->assertSame(200, $list->status, json_encode($list->payload));
        $this->assertSame(100, $list->payload['meta']['per_page']);
    }

    private function seedWebGroup(string $name): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_groups` (`type`, `name`, `flags`) VALUES (1, ?, 0)',
            DB_PREFIX
        ))->execute([$name]);
        return (int) $pdo->lastInsertId();
    }

    private function seedServerGroup(string $name): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_srvgroups` (`flags`, `immunity`, `name`, `groups_immune`) VALUES ("", 0, ?, "")',
            DB_PREFIX
        ))->execute([$name]);
        return (int) $pdo->lastInsertId();
    }
}
