<?php

// #96: password reset tokens (`:prefix_admins.validate`) never expired. The
// new `validate_until` column holds the deadline `auth.lost_password` sets,
// and `page.lostpassword.php` refuses a token past it. Tokens issued before
// this migration have no deadline, so they are refused: the admin requests
// a new link.
//
// Guarded by an information_schema existence check (same shape as 814.php)
// so re-running is a no-op.
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
    . "AND COLUMN_NAME = 'validate_until'"
);
$dbs->bind(':table', $dbs->getPrefix() . '_admins');
$row = $dbs->single();

if (!is_array($row) || (int) ($row['c'] ?? 0) === 0) {
    $dbs->query(
        'ALTER TABLE `:prefix_admins` '
        . 'ADD COLUMN `validate_until` datetime NULL DEFAULT NULL AFTER `validate`'
    );
    $dbs->execute();
}

return true;
