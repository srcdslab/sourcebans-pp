<?php

// #54: browser sessions are now persisted in `:prefix_login_tokens` so they
// can be revoked server-side. The new `aid` column ties each session to its
// admin, which lets a password change, a password reset, a deactivation or
// a deletion end every session of that admin.
//
// Guarded by an information_schema existence check (same shape as 811.php)
// so re-running is a no-op. The table held no rows before this change
// (`Auth::insertNewToken()` was never called), so no backfill is needed.
//
// `$this` is supplied by Updater::update(), which loads this file inside
// the Updater instance scope; PHPStan can't see that, so `$this->dbs`
// reads below are suppressed inline.

// @phpstan-ignore variable.undefined
$dbs = $this->dbs;

$dbs->query(
    'SELECT COUNT(*) AS c FROM information_schema.COLUMNS '
    . 'WHERE TABLE_SCHEMA = DATABASE() '
    . 'AND TABLE_NAME = :table '
    . "AND COLUMN_NAME = 'aid'"
);
$dbs->bind(':table', $dbs->getPrefix() . '_login_tokens');
$row = $dbs->single();

if (!is_array($row) || (int) ($row['c'] ?? 0) === 0) {
    $dbs->query(
        'ALTER TABLE `:prefix_login_tokens` '
        . 'ADD COLUMN `aid` int(6) NOT NULL DEFAULT 0 AFTER `jti`, '
        . 'ADD KEY `aid` (`aid`)'
    );
    $dbs->execute();
}

return true;
