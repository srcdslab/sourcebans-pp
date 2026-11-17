<?php

// #97: per-address login throttling. Each row counts the password logins
// one client address (IPv6 cut to /64) attempted in the current window;
// see Sbpp\Auth\LoginThrottle. Rows are short-lived and garbage-collected
// by the login handler, so there is nothing to backfill.
//
// CHARSET is hardcoded utf8mb4 (same as 812.php): native prepares cannot
// bind a charset name. `CREATE TABLE IF NOT EXISTS` keeps re-runs a no-op.
//
// `$this` is supplied by Updater::update(), which loads this file inside
// the Updater instance scope; PHPStan can't see that, so `$this->dbs`
// reads below are suppressed inline.

// @phpstan-ignore variable.undefined
$this->dbs->query(
    'CREATE TABLE IF NOT EXISTS `:prefix_login_throttle` ('
    . '`ip` varchar(32) NOT NULL,'
    . '`attempts` int(10) UNSIGNED NOT NULL DEFAULT 0,'
    . '`window_start` int(11) NOT NULL,'
    . 'PRIMARY KEY (`ip`),'
    . 'KEY `window_start` (`window_start`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);
// @phpstan-ignore variable.undefined
$this->dbs->execute();

return true;
