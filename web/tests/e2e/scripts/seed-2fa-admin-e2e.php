<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

/**
 * E2E seeder for the two-factor spec (#107): a dedicated admin with a
 * known password, so turning 2FA on (which ends the admin's other
 * sessions) never touches the shared seeded `admin` the other specs sign
 * in as. Prints `{"user": "...", "password": "..."}`.
 *
 * Usage (inside the web container): php seed-2fa-admin-e2e.php <user>
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "seed-2fa-admin-e2e.php must run on the CLI.\n");
    exit(2);
}

if (!getenv('DB_NAME')) {
    putenv('DB_NAME=sourcebans_e2e');
    $_ENV['DB_NAME']    = 'sourcebans_e2e';
    $_SERVER['DB_NAME'] = 'sourcebans_e2e';
}

if (getenv('DB_NAME') === 'sourcebans_test' || getenv('DB_NAME') === 'sourcebans') {
    fwrite(STDERR, 'refusing to seed against DB_NAME=' . getenv('DB_NAME') . ": this script must target the e2e DB.\n");
    exit(2);
}

require __DIR__ . '/../../bootstrap.php';

if (!isset($GLOBALS['PDO'])) {
    $GLOBALS['PDO'] = new \Database(DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS, DB_PREFIX, DB_CHARSET);
}

/** @var \Database $pdo */
$pdo = $GLOBALS['PDO'];

$user = (string) ($argv[1] ?? '');
if (!preg_match('/^e2e-2fa-[a-z0-9-]{1,40}$/D', $user)) {
    fwrite(STDERR, "usage: seed-2fa-admin-e2e.php e2e-2fa-<suffix>\n");
    exit(2);
}
$password = 'pw-' . bin2hex(random_bytes(8));

// Re-runs start from a clean account: drop any earlier row and its 2FA.
$pdo->query('SELECT aid FROM `:prefix_admins` WHERE user = :user');
$pdo->bind(':user', $user);
$old = $pdo->single();
if (is_array($old)) {
    foreach (['admin_totp', 'admin_recovery_codes', 'auth_pending', 'login_tokens'] as $table) {
        $pdo->query("DELETE FROM `:prefix_{$table}` WHERE aid = :aid");
        $pdo->bind(':aid', (int) $old['aid']);
        $pdo->execute();
    }
    $pdo->query('DELETE FROM `:prefix_admins` WHERE aid = :aid');
    $pdo->bind(':aid', (int) $old['aid']);
    $pdo->execute();
}

$pdo->query(
    'INSERT INTO `:prefix_admins` (user, authid, password, gid, email, validate, extraflags, immunity)
     VALUES (:user, \'\', :password, -1, :email, NULL, 0, 0)'
);
$pdo->bind(':user', $user);
$pdo->bind(':password', password_hash($password, PASSWORD_BCRYPT));
$pdo->bind(':email', $user . '@example.test');
$pdo->execute();

echo json_encode(['user' => $user, 'password' => $password], JSON_THROW_ON_ERROR), "\n";
