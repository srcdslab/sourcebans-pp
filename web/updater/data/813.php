<?php

// Configurable password generator defaults (`Sbpp\Security\PasswordGenerator`).
// Fresh installs get the same rows via `web/install/includes/sql/data.sql`;
// this migration backfills upgrades. INSERT IGNORE keeps any value an
// operator already set and makes re-runs a no-op.
//
// `$this` is supplied by Updater::update(), which loads this file inside
// the Updater instance scope; PHPStan can't see that, so `$this->dbs`
// reads below are suppressed inline.

// @phpstan-ignore variable.undefined
$this->dbs->query(
    "INSERT IGNORE INTO `:prefix_settings` (`setting`, `value`) VALUES
    ('config.password.generator.length', '20'),
    ('config.password.generator.lowercase', '1'),
    ('config.password.generator.uppercase', '1'),
    ('config.password.generator.digits', '1'),
    ('config.password.generator.symbols', '1'),
    ('config.password.generator.exclude_ambiguous', '1')"
);
// @phpstan-ignore variable.undefined
$this->dbs->execute();

return true;
