<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.
/**
 * E2E ban-demo seeder.
 *
 * Writes an opaque payload under `SB_DEMOS` and inserts the matching
 * `:prefix_demos` row (`demtype = 'B'`) so `getdemo.php?type=B&id=<bid>`
 * and the banlist row / drawer "Download demo" affordances have
 * something real to serve. Mirrors `Sbpp\Tests\Synthesizer`'s demo
 * insert shape (`INSERT INTO :prefix_demos (demid, demtype, filename,
 * origname)`), but scoped to a single caller-supplied bid instead of
 * a whole synthetic dataset.
 *
 * Why a PHP shim instead of writing the file straight from Playwright
 * (as upstream sbpp/sourcebans-pp's `ban-demo-download.spec.ts` does
 * via `node:fs/promises` against `resolve(process.cwd(), '../../demos')`):
 * this suite runs in two modes (`E2E_IN_CONTAINER=1` inside the web
 * container, or host-side through `docker compose exec`), and only
 * the PHP side reliably resolves `SB_DEMOS` the same way `getdemo.php`
 * does in both modes. A Node-side relative path guess would silently
 * diverge from the real serving directory under host-side execution.
 *
 * Same e2e-only guardrail as the sibling shims: refuses any DB other
 * than the e2e schema (default `sourcebans_e2e`).
 *
 * Usage (inside the web container):
 *
 *   echo '{"bid":42,"filename":"<32-hex-or-any-basename>","origname":"evidence.dem"}' | php seed-ban-demo-e2e.php
 *
 * `filename` is the on-disk basename (caller picks it — tests use a
 * deterministic per-worker/per-retry value so parallel runs and
 * retries never collide on the same file); `origname` is what the
 * browser should see as the downloaded filename. Both are basename()'d
 * server-side before touching the filesystem, mirroring the same
 * defensiveness `getdemo.php` / `UploadHandler` apply to a DB-sourced
 * filename.
 *
 * Caller responsibility: the bid must already exist (seed the ban via
 * `seedBanViaApi` first). Cleanup: call the `bans.remove_demo` JSON
 * action (`Actions.BansRemoveDemo`) from the spec — it unlinks the
 * on-disk file AND deletes the `:prefix_demos` row in one step, same
 * as the panel's own "remove demo" affordance.
 *
 * Output on stdout (single JSON line):
 *
 *   {"bid":42,"filename":"...","origname":"evidence.dem"}
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "seed-ban-demo-e2e.php must run on the CLI.\n");
    exit(2);
}

if (!getenv('DB_NAME')) {
    putenv('DB_NAME=sourcebans_e2e');
    $_ENV['DB_NAME']    = 'sourcebans_e2e';
    $_SERVER['DB_NAME'] = 'sourcebans_e2e';
}

if (getenv('DB_NAME') === 'sourcebans_test' || getenv('DB_NAME') === 'sourcebans') {
    fwrite(STDERR, "refusing to seed a ban demo against DB_NAME=" . getenv('DB_NAME')
        . ": this script must target a dedicated e2e DB (default sourcebans_e2e).\n");
    exit(2);
}

require __DIR__ . '/../../bootstrap.php';

if (!isset($GLOBALS['PDO'])) {
    $GLOBALS['PDO'] = new \Database(DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS, DB_PREFIX, DB_CHARSET);
}

$payload = stream_get_contents(STDIN);
if ($payload === false || trim($payload) === '') {
    fwrite(STDERR, "seed-ban-demo-e2e.php: empty stdin payload.\n");
    exit(2);
}

$decoded = json_decode($payload, true);
if (!is_array($decoded)) {
    fwrite(STDERR, "seed-ban-demo-e2e.php: stdin is not a JSON object.\n");
    exit(2);
}

$bid = (int) ($decoded['bid'] ?? 0);
if ($bid <= 0) {
    fwrite(STDERR, "seed-ban-demo-e2e.php: missing or invalid `bid` in payload.\n");
    exit(2);
}

$filename = basename((string) ($decoded['filename'] ?? ''));
if ($filename === '') {
    fwrite(STDERR, "seed-ban-demo-e2e.php: missing or invalid `filename` in payload.\n");
    exit(2);
}

$origname = (string) ($decoded['origname'] ?? $filename);

if (!is_dir(SB_DEMOS)) {
    if (!@mkdir(SB_DEMOS, 0775, true) && !is_dir(SB_DEMOS)) {
        fwrite(STDERR, "seed-ban-demo-e2e.php: SB_DEMOS (" . SB_DEMOS . ") does not exist and could not be created.\n");
        exit(2);
    }
}

$path = SB_DEMOS . DIRECTORY_SEPARATOR . $filename;
if (file_put_contents($path, "sourcebans++ e2e demo payload\n") === false) {
    fwrite(STDERR, "seed-ban-demo-e2e.php: failed to write demo payload to $path.\n");
    exit(2);
}

$GLOBALS['PDO']->query(
    'REPLACE INTO `:prefix_demos` (`demid`, `demtype`, `filename`, `origname`) VALUES (?, ?, ?, ?)'
);
$GLOBALS['PDO']->execute([$bid, 'B', $filename, $origname]);

$result = [
    'bid'      => $bid,
    'filename' => $filename,
    'origname' => $origname,
];

fwrite(STDOUT, json_encode($result, JSON_UNESCAPED_SLASHES) . "\n");
