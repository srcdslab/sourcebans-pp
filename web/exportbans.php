<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

// Permanent-ban export as SRCDS config files:
//   exportbans.php?type=steam  ->  banned_user.cfg (`banid 0 <steamid>`)
//   exportbans.php?type=ip     ->  banned_ip.cfg   (`addip 0 <ip>`)
// Owners always; everyone else only when `config.exportpublic` is on.

include_once("init.php");

/** Plain-text error response. */
function exportbans_die(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}

if (!$userbank->HasAccess(WebPermission::Owner) && !Config::getBool('config.exportpublic')) {
    exportbans_die(403, "You don't have access to this feature.");
}

$type = (string) ($_GET['type'] ?? '');
[$filename, $sql, $column, $command] = match ($type) {
    'steam' => [
        'banned_user.cfg',
        "SELECT authid FROM `:prefix_bans` WHERE length = '0' AND RemoveType IS NULL AND type = '0'",
        'authid',
        'banid 0',
    ],
    'ip' => [
        'banned_ip.cfg',
        "SELECT ip FROM `:prefix_bans` WHERE length = '0' AND RemoveType IS NULL AND type = '1'",
        'ip',
        'addip 0',
    ],
    default => exportbans_die(400, 'Unknown export type. Expected "steam" or "ip".'),
};

// A .cfg is plain text. The old `application/x-httpd-php` isn't a
// valid media type for it (#60).
header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Content-Disposition: attachment; filename="' . $filename . '"');

foreach ($GLOBALS['PDO']->query($sql)->iterate() as $ban) {
    print($command . ' ' . $ban[$column] . "\r\n");
}
