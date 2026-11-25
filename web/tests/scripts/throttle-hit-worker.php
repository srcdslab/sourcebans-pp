<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

/**
 * One concurrent client for LoginThrottleTest::testConcurrentHitsEachGetTheirOwnCount
 * (#106). Opens its own connection, waits for the shared start time, then
 * calls LoginThrottle::hit() `<hits>` times on `<key>` and prints each
 * returned count on its own line.
 *
 * Usage: php throttle-hit-worker.php <key> <hits> <start unix time, float>
 * DB_* come from the environment, as in tests/bootstrap.php.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/includes/vendor/autoload.php';

[, $key, $hits, $startAt] = $argv + [null, '', '0', '0'];

$db = new \Sbpp\Db\Database(
    getenv('DB_HOST') ?: 'db',
    (int) (getenv('DB_PORT') ?: 3306),
    getenv('DB_NAME') ?: 'sourcebans_test',
    getenv('DB_USER') ?: 'sourcebans',
    getenv('DB_PASS') ?: 'sourcebans',
    getenv('DB_PREFIX') ?: 'sb',
    getenv('DB_CHARSET') ?: 'utf8mb4',
);
$throttle = new \Sbpp\Auth\LoginThrottle($db);

while (microtime(true) < (float) $startAt) {
    usleep(200);
}
for ($i = 0; $i < (int) $hits; $i++) {
    echo $throttle->hit((string) $key, 100000, 900, time())->count, "\n";
}
