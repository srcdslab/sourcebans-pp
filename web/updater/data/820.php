<?php

// #107: two-factor authentication. Tables for the TOTP secret, the
// recovery codes and the pending second sign-in step (see
// Sbpp\Auth\TwoFactor), and the `auth.2fa.require` setting, off by default
// (same default as data.sql). Every statement is a no-op on a re-run.
//
// CHARSET is hardcoded utf8mb4 (same as 812.php / 818.php / 819.php):
// native prepares cannot bind a charset name.
//
// `$this` is supplied by Updater::update(), which loads this file inside
// the Updater instance scope; PHPStan can't see that, so `$this->dbs`
// reads below are suppressed inline.

$statements = [
    'CREATE TABLE IF NOT EXISTS `:prefix_admin_totp` ('
    . '`aid` int(6) NOT NULL,'
    . '`secret` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`confirmed_at` int(11) DEFAULT NULL,'
    . '`last_step` bigint(20) NOT NULL DEFAULT -1,'
    . '`created` int(11) NOT NULL,'
    . 'PRIMARY KEY (`aid`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',

    'CREATE TABLE IF NOT EXISTS `:prefix_admin_recovery_codes` ('
    . '`id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,'
    . '`aid` int(6) NOT NULL,'
    . '`code_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`used_at` int(11) DEFAULT NULL,'
    . 'PRIMARY KEY (`id`),'
    . 'KEY `aid` (`aid`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',

    'CREATE TABLE IF NOT EXISTS `:prefix_auth_pending` ('
    . '`token_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`aid` int(6) NOT NULL,'
    . '`purpose` varchar(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`maxlife` int(11) NOT NULL,'
    . "`redirect` varchar(255) NOT NULL DEFAULT '',"
    . '`attempts` int(10) UNSIGNED NOT NULL DEFAULT 0,'
    . '`expires` int(11) NOT NULL,'
    . 'PRIMARY KEY (`token_hash`),'
    . 'KEY `aid` (`aid`),'
    . 'KEY `expires` (`expires`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',

    "INSERT IGNORE INTO `:prefix_settings` (`setting`, `value`) VALUES ('auth.2fa.require', 'off')",
];

foreach ($statements as $sql) {
    // @phpstan-ignore variable.undefined
    $this->dbs->query($sql);
    // @phpstan-ignore variable.undefined
    $this->dbs->execute();
}

return true;
