<?php

namespace Sbpp\Tests\Api;

use Sbpp\Tests\Fixture;

final class RestCommentsTest extends RestTestCase
{
    public function testCreateReturnsCommentCidWhenLogAutoIncrementHasDiverged(): void
    {
        $bid = $this->seedBan('STEAM_0:1:9510');
        $pdo = Fixture::rawPdo();
        $insertLog = $pdo->prepare(sprintf(
            'INSERT INTO `%s_log` (`type`, `title`, `message`, `function`, `query`, `aid`, `host`, `created`)
             VALUES ("m", "dummy", "dummy", "", "", -1, "", UNIX_TIMESTAMP())',
            DB_PREFIX
        ));
        for ($i = 0; $i < 5; $i++) {
            $insertLog->execute();
        }

        $token = $this->mintToken();
        $created = $this->rest('POST', '/bans/' . $bid . '/comments', [
            'body' => 'cid contract',
        ], $token);
        $this->assertSame(201, $created->status, json_encode($created->payload));
        $id = (int) $created->payload['data']['id'];

        $commentCid = (int) $pdo->query(sprintf(
            'SELECT cid FROM `%s_comments` WHERE bid = %d AND type = "B" ORDER BY cid DESC LIMIT 1',
            DB_PREFIX,
            $bid
        ))->fetchColumn();
        $maxLid = (int) $pdo->query(sprintf(
            'SELECT MAX(lid) FROM `%s_log`',
            DB_PREFIX
        ))->fetchColumn();

        $this->assertSame($commentCid, $id);
        $this->assertNotSame($maxLid, $id);
        $this->assertSame('cid contract', $created->payload['data']['body']);
    }

    public function testCreateListPatchDeleteOnBan(): void
    {
        $bid = $this->seedBan('STEAM_0:1:9501');
        $token = $this->mintToken();

        $created = $this->rest('POST', '/bans/' . $bid . '/comments', [
            'body' => 'rest comment',
        ], $token);
        $this->assertSame(201, $created->status, json_encode($created->payload));
        $comment = $created->payload['data'];
        $this->assertSame('rest comment', $comment['body']);
        $this->assertSame('ban', $comment['type']);
        $this->assertSame($bid, $comment['parent_id']);
        $this->assertSame('admin', $comment['author']);
        $this->assertSame(Fixture::adminAid(), $comment['author_aid']);

        $list = $this->rest('GET', '/bans/' . $bid . '/comments', token: $token);
        $this->assertSame(200, $list->status);
        $this->assertSame(1, $list->payload['meta']['total']);
        $this->assertSame($comment['id'], $list->payload['data'][0]['id']);

        $anon = $this->rest('GET', '/bans/' . $bid . '/comments');
        $this->assertSame(200, $anon->status);
        $this->assertSame(0, $anon->payload['meta']['total']);

        $patched = $this->rest('PATCH', '/comments/' . $comment['id'], [
            'body' => 'edited comment',
        ], $token);
        $this->assertSame(200, $patched->status, json_encode($patched->payload));
        $this->assertSame('edited comment', $patched->payload['data']['body']);
        $this->assertNotNull($patched->payload['data']['edited_at']);

        $deleted = $this->rest('DELETE', '/comments/' . $comment['id'], [], $token);
        $this->assertSame(200, $deleted->status, json_encode($deleted->payload));
        $gone = $this->rest('GET', '/bans/' . $bid . '/comments', token: $token);
        $this->assertSame(0, $gone->payload['meta']['total']);
    }

    public function testAnonymousSeesCommentsWhenPublicEnabled(): void
    {
        $bid = $this->seedBan('STEAM_0:1:9502');
        $token = $this->mintToken();
        $created = $this->rest('POST', '/bans/' . $bid . '/comments', [
            'body' => 'public comment',
        ], $token);
        $this->assertSame(201, $created->status);

        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'REPLACE INTO `%s_settings` (`value`, `setting`) VALUES ("1", "config.enablepubliccomments")',
            DB_PREFIX
        ))->execute();
        \Config::init($GLOBALS['PDO']);

        $anon = $this->rest('GET', '/bans/' . $bid . '/comments');
        $this->assertSame(200, $anon->status, json_encode($anon->payload));
        $this->assertSame(1, $anon->payload['meta']['total']);
        $this->assertSame('public comment', $anon->payload['data'][0]['body']);
        $this->assertNull($anon->payload['data'][0]['author']);
        $this->assertNull($anon->payload['data'][0]['author_aid']);
    }

    public function testAnonymousGetCommCommentsIs404WhenCommsDisabled(): void
    {
        $cid = $this->seedComm('STEAM_0:1:9506');
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'REPLACE INTO `%s_settings` (`value`, `setting`) VALUES ("0", "config.enablecomms")',
            DB_PREFIX
        ))->execute();
        \Config::init($GLOBALS['PDO']);

        $anon = $this->rest('GET', '/comms/' . $cid . '/comments');
        $this->assertRestError($anon, 404, 'not_found');

        $token = $this->mintToken();
        $pat = $this->rest('GET', '/comms/' . $cid . '/comments', token: $token);
        $this->assertSame(200, $pat->status, json_encode($pat->payload));

        $pdo->prepare(sprintf(
            'REPLACE INTO `%s_settings` (`value`, `setting`) VALUES ("1", "config.enablecomms")',
            DB_PREFIX
        ))->execute();
        \Config::init($GLOBALS['PDO']);
    }

    public function testCreateOnComm(): void
    {
        $cid = $this->seedComm('STEAM_0:1:9503');
        $token = $this->mintToken();
        $created = $this->rest('POST', '/comms/' . $cid . '/comments', [
            'body' => 'comm comment',
        ], $token);
        $this->assertSame(201, $created->status, json_encode($created->payload));
        $this->assertSame('comm', $created->payload['data']['type']);
        $this->assertSame($cid, $created->payload['data']['parent_id']);
    }

    public function testEmptyBodyIs400(): void
    {
        $bid = $this->seedBan('STEAM_0:1:9504');
        $token = $this->mintToken();
        $response = $this->rest('POST', '/bans/' . $bid . '/comments', [
            'body' => '   ',
        ], $token);
        $this->assertRestError($response, 400, 'validation');
        $this->assertSame('body', $response->payload['error']['field'] ?? null);
    }

    public function testMissingParentIs404(): void
    {
        $token = $this->mintToken();
        $response = $this->rest('POST', '/bans/999999/comments', [
            'body' => 'x',
        ], $token);
        $this->assertRestError($response, 404, 'not_found');
    }

    public function testDeleteRequiresOwner(): void
    {
        $bid = $this->seedBan('STEAM_0:1:9505');
        $ownerToken = $this->mintToken();
        $created = $this->rest('POST', '/bans/' . $bid . '/comments', [
            'body' => 'owner comment',
        ], $ownerToken);
        $this->assertSame(201, $created->status);
        $id = $created->payload['data']['id'];

        $pdo = Fixture::rawPdo();
        $hash = password_hash('other', PASSWORD_BCRYPT);
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_admins` (user, authid, password, gid, email, extraflags, immunity, enabled)
             VALUES (?, ?, ?, -1, ?, ?, 0, 1)',
            DB_PREFIX
        ))->execute(['commenter', 'STEAM_0:0:9505', $hash, 'commenter@example.test', ADMIN_ADD_BAN]);
        $aid = (int) $pdo->lastInsertId();
        $otherToken = $this->mintToken($aid);

        $denied = $this->rest('DELETE', '/comments/' . $id, [], $otherToken);
        $this->assertRestError($denied, 403, 'forbidden');
    }

    public function testPatchIsAuthorOrOwner(): void
    {
        $bid = $this->seedBan('STEAM_0:1:9507');
        $authorAid = $this->insertAdmin('comment-author', 'STEAM_0:0:9507', ADMIN_ADD_BAN);
        $otherAid = $this->insertAdmin('comment-other', 'STEAM_0:0:9508', ADMIN_ADD_BAN);
        $authorToken = $this->mintToken($authorAid);
        $otherToken = $this->mintToken($otherAid);
        $ownerToken = $this->mintToken();

        $mine = $this->rest('POST', '/bans/' . $bid . '/comments', [
            'body' => 'authors comment',
        ], $authorToken);
        $this->assertSame(201, $mine->status, json_encode($mine->payload));
        $id = $mine->payload['data']['id'];

        $denied = $this->rest('PATCH', '/comments/' . $id, [
            'body' => 'hijack',
        ], $otherToken);
        $this->assertRestError($denied, 403, 'forbidden');

        $own = $this->rest('PATCH', '/comments/' . $id, [
            'body' => 'author edit',
        ], $authorToken);
        $this->assertSame(200, $own->status, json_encode($own->payload));
        $this->assertSame('author edit', $own->payload['data']['body']);

        $asOwner = $this->rest('PATCH', '/comments/' . $id, [
            'body' => 'owner edit',
        ], $ownerToken);
        $this->assertSame(200, $asOwner->status, json_encode($asOwner->payload));
        $this->assertSame('owner edit', $asOwner->payload['data']['body']);
    }

    public function testMissingCommentIs404(): void
    {
        $token = $this->mintToken();
        $response = $this->rest('PATCH', '/comments/999999', ['body' => 'x'], $token);
        $this->assertRestError($response, 404, 'not_found');
    }

    private function seedBan(string $steam): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_bans` (created, type, ip, authid, name, ends, length, reason, aid, adminIp, admin_name)
             VALUES (UNIX_TIMESTAMP(), 0, ?, ?, ?, UNIX_TIMESTAMP(), 0, ?, ?, "127.0.0.1", ?)',
            DB_PREFIX
        ))->execute(['1.1.1.1', $steam, 'Cheater', 'test', Fixture::adminAid(), 'admin']);
        return (int) $pdo->lastInsertId();
    }

    private function insertAdmin(string $user, string $steam, int $flags): int
    {
        $pdo = Fixture::rawPdo();
        $hash = password_hash('other', PASSWORD_BCRYPT);
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_admins` (user, authid, password, gid, email, extraflags, immunity, enabled)
             VALUES (?, ?, ?, -1, ?, ?, 0, 1)',
            DB_PREFIX
        ))->execute([$user, $steam, $hash, $user . '@example.test', $flags]);
        return (int) $pdo->lastInsertId();
    }

    private function seedComm(string $steam): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_comms` (created, type, authid, name, ends, length, reason, aid, adminIp, admin_name)
             VALUES (UNIX_TIMESTAMP(), ?, ?, ?, UNIX_TIMESTAMP(), 0, ?, ?, "127.0.0.1", ?)',
            DB_PREFIX
        ))->execute([1, $steam, 'Player', 'test', Fixture::adminAid(), 'admin']);
        return (int) $pdo->lastInsertId();
    }
}
