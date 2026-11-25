<?php

// #106: sign-in counters per address, username and device cookie replace
// the per-account lockout. `:prefix_auth_throttle` takes over from
// `:prefix_login_throttle` (818, per address only): keys are typed
// (`ip:`, `n:`, `d:`, `lpi:`, `lpa:`) and each row carries its own window
// end, since the counters use different windows. The old rows are
// short-lived, so there is nothing to carry over.
//
// `:prefix_admins.attempts` / `lockout_until` are no longer read; they are
// cleared so no account stays locked by the old rule. The columns stay:
// older code reading them keeps working.
//
// CHARSET is hardcoded utf8mb4 (same as 812.php / 818.php): native
// prepares cannot bind a charset name. Every statement is a no-op on a
// re-run.
//
// `$this` is supplied by Updater::update(), which loads this file inside
// the Updater instance scope; PHPStan can't see that, so `$this->dbs`
// reads below are suppressed inline.

// @phpstan-ignore variable.undefined
$this->dbs->query(
    'CREATE TABLE IF NOT EXISTS `:prefix_auth_throttle` ('
    . '`throttle_key` varchar(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'
    . '`attempts` int(10) UNSIGNED NOT NULL DEFAULT 0,'
    . '`expires` int(11) NOT NULL,'
    . 'PRIMARY KEY (`throttle_key`),'
    . 'KEY `expires` (`expires`)'
    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);
// @phpstan-ignore variable.undefined
$this->dbs->execute();

// @phpstan-ignore variable.undefined
$this->dbs->query('DROP TABLE IF EXISTS `:prefix_login_throttle`');
// @phpstan-ignore variable.undefined
$this->dbs->execute();

// @phpstan-ignore variable.undefined
$this->dbs->query('UPDATE `:prefix_admins` SET attempts = 0, lockout_until = NULL WHERE attempts <> 0 OR lockout_until IS NOT NULL');
// @phpstan-ignore variable.undefined
$this->dbs->execute();

return true;
