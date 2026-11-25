<?php

// #108: passkeys (WebAuthn). The credential records and the single-use
// challenges, see Sbpp\Auth\Passkeys. Nothing to backfill; every statement
// is a no-op on a re-run.
//
// CHARSET is hardcoded utf8mb4 (same as 812.php / 818.php - 820.php):
// native prepares cannot bind a charset name.
//
// `$this` is supplied by Updater::update(), which loads this file inside
// the Updater instance scope; PHPStan can't see that, so `$this->dbs`
// reads below are suppressed inline.

$statements = [
    'CREATE TABLE IF NOT EXISTS `:prefix_admin_passkeys` ('
    . '`id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,'
    . '`aid` int(6) NOT NULL,'
    . '`credential_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`name` varchar(64) NOT NULL,'
    . '`record` text NOT NULL,'
    . '`created` int(11) NOT NULL,'
    . '`last_used` int(11) DEFAULT NULL,'
    . 'PRIMARY KEY (`id`),'
    . 'UNIQUE KEY `credential_hash` (`credential_hash`),'
    . 'KEY `aid` (`aid`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',

    'CREATE TABLE IF NOT EXISTS `:prefix_webauthn_challenges` ('
    . '`token_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`purpose` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`aid` int(6) NOT NULL DEFAULT 0,'
    . '`options` text NOT NULL,'
    . '`expires` int(11) NOT NULL,'
    . 'PRIMARY KEY (`token_hash`),'
    . 'KEY `expires` (`expires`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
];

foreach ($statements as $sql) {
    // @phpstan-ignore variable.undefined
    $this->dbs->query($sql);
    // @phpstan-ignore variable.undefined
    $this->dbs->execute();
}

return true;
