<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Rest;

use Sbpp\Api\ApiError;
use Sbpp\Db\Database;

/**
 * Read-only group catalog for REST clients that map external roles to
 * SourceBans web / SourceMod groups.
 */
final class GroupsService
{
    /**
     * @param array<string, mixed> $query
     * @return array{
     *     data: array{web: list<array{id: int, name: string, flags: int}>, server: list<array{id: int, name: string, flags: string, immunity: int}>},
     *     meta: array{page: int, per_page: int, web_total: int, server_total: int}
     * }
     */
    public function list(array $query): array
    {
        $kind = strtolower(trim((string) ($query['kind'] ?? '')));
        if ($kind !== '' && $kind !== 'web' && $kind !== 'server') {
            throw new ApiError('validation', 'kind must be web or server.', 'kind', 400);
        }

        $page = max(1, (int) ($query['page'] ?? 1));
        $perPage = (int) ($query['per_page'] ?? 100);
        if ($perPage < 1) {
            $perPage = 100;
        }
        $perPage = min(100, $perPage);
        $offset = ($page - 1) * $perPage;

        $pdo = $this->db();
        $webRows = $pdo->query(
            'SELECT gid, name, flags FROM `:prefix_groups` WHERE type = 1 ORDER BY name ASC'
        )->resultset();
        $web = [];
        foreach ($webRows as $row) {
            $web[] = [
                'id' => (int) $row['gid'],
                'name' => (string) $row['name'],
                'flags' => (int) $row['flags'],
            ];
        }

        $srvRows = $pdo->query(
            'SELECT id, name, flags, immunity FROM `:prefix_srvgroups` ORDER BY name ASC'
        )->resultset();
        $server = [];
        foreach ($srvRows as $row) {
            $server[] = [
                'id' => (int) $row['id'],
                'name' => (string) $row['name'],
                'flags' => (string) $row['flags'],
                'immunity' => (int) $row['immunity'],
            ];
        }

        $webSlice = $kind === 'server' ? [] : array_slice($web, $offset, $perPage);
        $serverSlice = $kind === 'web' ? [] : array_slice($server, $offset, $perPage);

        return [
            'data' => [
                'web' => $webSlice,
                'server' => $serverSlice,
            ],
            'meta' => [
                'page' => $page,
                'per_page' => $perPage,
                'web_total' => count($web),
                'server_total' => count($server),
            ],
        ];
    }

    private function db(): Database
    {
        $pdo = $GLOBALS['PDO'] ?? null;
        if ($pdo instanceof Database) {
            return $pdo;
        }
        return new Database(DB_HOST, (int) DB_PORT, DB_NAME, DB_USER, DB_PASS, DB_PREFIX, DB_CHARSET);
    }
}
