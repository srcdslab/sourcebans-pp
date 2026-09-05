<?php

namespace Sbpp\Tests\Api;

use Sbpp\Tests\Fixture;

final class RestProtestsTest extends RestTestCase
{
    public function testListRequiresToken(): void
    {
        $response = $this->rest('GET', '/protests');
        $this->assertRestError($response, 401, 'unauthorized');
    }

    public function testCookieJwtDoesNotList(): void
    {
        $this->loginAsAdmin();
        $response = $this->rest('GET', '/protests');
        $this->assertRestError($response, 401, 'unauthorized');
    }

    public function testListGetDelete(): void
    {
        $current = $this->seedProtest('0');
        $archived = $this->seedProtest('1');
        $token = $this->mintToken();

        $list = $this->rest('GET', '/protests', token: $token);
        $this->assertSame(200, $list->status, json_encode($list->payload));
        $ids = array_column($list->payload['data'], 'id');
        $this->assertContains($current, $ids);
        $this->assertNotContains($archived, $ids);

        $archiveList = $this->rest('GET', '/protests', token: $token, query: ['archived' => 'true']);
        $this->assertSame(200, $archiveList->status);
        $archiveIds = array_column($archiveList->payload['data'], 'id');
        $this->assertContains($archived, $archiveIds);
        $this->assertNotContains($current, $archiveIds);

        $got = $this->rest('GET', '/protests/' . $current, token: $token);
        $this->assertSame(200, $got->status);
        $this->assertSame($current, $got->payload['data']['id']);
        $this->assertSame('wrong ban', $got->payload['data']['reason']);
        $this->assertFalse($got->payload['data']['archived']);
        $this->assertSame('127.0.0.1', $got->payload['data']['ip']);
        $this->assertSame('protest@example.test', $got->payload['data']['email']);

        $archivedLive = $this->rest('POST', '/protests/' . $current . '/archive', [], $token);
        $this->assertSame(200, $archivedLive->status, json_encode($archivedLive->payload));
        $this->assertTrue($archivedLive->payload['data']['archived']);

        $afterArchive = $this->rest('GET', '/protests', token: $token);
        $this->assertNotContains($current, array_column($afterArchive->payload['data'], 'id'));
        $archiveAfter = $this->rest('GET', '/protests', token: $token, query: ['archived' => 'true']);
        $this->assertContains($current, array_column($archiveAfter->payload['data'], 'id'));

        $restored = $this->rest('POST', '/protests/' . $current . '/restore', [], $token);
        $this->assertSame(200, $restored->status, json_encode($restored->payload));
        $this->assertFalse($restored->payload['data']['archived']);
        $afterRestore = $this->rest('GET', '/protests', token: $token);
        $this->assertContains($current, array_column($afterRestore->payload['data'], 'id'));

        $deleted = $this->rest('DELETE', '/protests/' . $current, [], $token);
        $this->assertSame(200, $deleted->status, json_encode($deleted->payload));
        $missing = $this->rest('GET', '/protests/' . $current, token: $token);
        $this->assertRestError($missing, 404, 'not_found');
    }

    public function testMissingIs404(): void
    {
        $token = $this->mintToken();
        $response = $this->rest('GET', '/protests/999999', token: $token);
        $this->assertRestError($response, 404, 'not_found');
        $this->assertRestError(
            $this->rest('POST', '/protests/999999/archive', [], $token),
            404,
            'not_found',
        );
        $this->assertRestError(
            $this->rest('POST', '/protests/999999/restore', [], $token),
            404,
            'not_found',
        );
    }

    private function seedProtest(string $archiv = '0'): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_protests`
              (`bid`, `email`, `reason`, `archiv`, `datesubmitted`, `pip`)
             VALUES (0, ?, ?, ?, ?, "127.0.0.1")',
            DB_PREFIX
        ))->execute(['protest@example.test', 'wrong ban', $archiv, time()]);
        return (int) $pdo->lastInsertId();
    }
}
