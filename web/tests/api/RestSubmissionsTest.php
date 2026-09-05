<?php

namespace Sbpp\Tests\Api;

use Sbpp\Tests\Fixture;

final class RestSubmissionsTest extends RestTestCase
{
    public function testListRequiresToken(): void
    {
        $response = $this->rest('GET', '/submissions');
        $this->assertRestError($response, 401, 'unauthorized');
    }

    public function testListGetDelete(): void
    {
        $current = $this->seedSubmission('RestPlayer', 'STEAM_0:1:9401', '0');
        $archived = $this->seedSubmission('Archived', 'STEAM_0:1:9402', '1');
        $token = $this->mintToken();

        $list = $this->rest('GET', '/submissions', token: $token);
        $this->assertSame(200, $list->status, json_encode($list->payload));
        $ids = array_column($list->payload['data'], 'id');
        $this->assertContains($current, $ids);
        $this->assertNotContains($archived, $ids);

        $got = $this->rest('GET', '/submissions/' . $current, token: $token);
        $this->assertSame(200, $got->status);
        $data = $got->payload['data'];
        $this->assertSame($current, $data['id']);
        $this->assertSame('STEAM_0:1:9401', $data['steam']);
        $this->assertIsString($data['steam64']);
        $this->assertSame('RestPlayer', $data['player_name']);
        $this->assertFalse($data['archived']);
        $this->assertSame('RestPlayer@example.test', $data['email']);

        $archivedLive = $this->rest('POST', '/submissions/' . $current . '/archive', [], $token);
        $this->assertSame(200, $archivedLive->status, json_encode($archivedLive->payload));
        $this->assertTrue($archivedLive->payload['data']['archived']);
        $afterArchive = $this->rest('GET', '/submissions', token: $token);
        $this->assertNotContains($current, array_column($afterArchive->payload['data'], 'id'));
        $archiveAfter = $this->rest('GET', '/submissions', token: $token, query: ['archived' => 'true']);
        $this->assertContains($current, array_column($archiveAfter->payload['data'], 'id'));

        $restored = $this->rest('POST', '/submissions/' . $current . '/restore', [], $token);
        $this->assertSame(200, $restored->status, json_encode($restored->payload));
        $this->assertFalse($restored->payload['data']['archived']);

        $deleted = $this->rest('DELETE', '/submissions/' . $current, [], $token);
        $this->assertSame(200, $deleted->status, json_encode($deleted->payload));
        $missing = $this->rest('GET', '/submissions/' . $current, token: $token);
        $this->assertRestError($missing, 404, 'not_found');
    }

    public function testInvalidSteamIsNullOnGet(): void
    {
        $id = $this->seedSubmission('JunkSteam', 'not-a-steam-id', '0');
        $token = $this->mintToken();
        $got = $this->rest('GET', '/submissions/' . $id, token: $token);
        $this->assertSame(200, $got->status, json_encode($got->payload));
        $this->assertNull($got->payload['data']['steam']);
        $this->assertNull($got->payload['data']['steam64']);
        $this->assertSame('JunkSteam', $got->payload['data']['player_name']);
    }

    public function testMissingIs404(): void
    {
        $token = $this->mintToken();
        $response = $this->rest('GET', '/submissions/999999', token: $token);
        $this->assertRestError($response, 404, 'not_found');
        $this->assertRestError(
            $this->rest('POST', '/submissions/999999/archive', [], $token),
            404,
            'not_found',
        );
        $this->assertRestError(
            $this->rest('POST', '/submissions/999999/restore', [], $token),
            404,
            'not_found',
        );
    }

    private function seedSubmission(string $name, string $steamId, string $archiv): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_submissions`
              (`name`, `SteamId`, `email`, `reason`, `archiv`, `submitted`, `ModID`, `ip`, `server`)
             VALUES (?, ?, ?, ?, ?, ?, 0, "127.0.0.1", 0)',
            DB_PREFIX
        ))->execute([$name, $steamId, $name . '@example.test', 'cheating', $archiv, time()]);
        return (int) $pdo->lastInsertId();
    }
}
