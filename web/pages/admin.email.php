<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

if (!defined("IN_SB")) {
    echo "You should not be here. Only follow links!";
    die();
}

global $theme, $userbank;

require_once __DIR__ . '/_admin_edit_helpers.php';

new AdminTabs([], $userbank, $theme);

$type = (string) ($_GET['type'] ?? '');
$id   = (int) ($_GET['id'] ?? 0);

// The bans route admits any bans flag (ADD_BAN included). Reading a
// reporter's email needs the flag of the queue it came from, the same
// gate `system.send_mail` applies to the send itself (#55).
[$permission, $section] = match ($type) {
    's'     => [\WebPermission::BanSubmissions, 'submissions'],
    'p'     => [\WebPermission::BanProtests, 'protests'],
    default => [null, ''],
};

if ($permission === null || $id <= 0) {
    sbpp_admin_edit_die_with_toast('Invalid submission or protest. Please only follow links.', 'index.php?p=admin&c=bans');
    return;
}

$back = 'index.php?p=admin&c=bans&section=' . $section;

if (!$userbank->HasAccess(\WebPermission::mask(\WebPermission::Owner, $permission))) {
    sbpp_admin_edit_die_with_toast("You don't have access to this.", $back);
    return;
}

$GLOBALS['PDO']->query($type === 's'
    ? 'SELECT email FROM `:prefix_submissions` WHERE subid = :id'
    : 'SELECT email FROM `:prefix_protests` WHERE pid = :id');
$GLOBALS['PDO']->bind(':id', $id);
$row   = $GLOBALS['PDO']->single();
$email = (string) ($row['email'] ?? '');

if ($email === '') {
    sbpp_admin_edit_die_with_toast('There is no email address for this entry.', $back);
    return;
}

// $type is the literal 's' or 'p' (match above) and $id is an int, so
// the `CheckEmail('s', 42)` expression carries no caller-controlled data
// and is safe in the template's onclick attribute via {nofilter}.
$emailJs = "CheckEmail('" . $type . "', " . $id . ")";

echo '<div id="admin-page-content"><div id="1">';
\Sbpp\View\Renderer::render($theme, new \Sbpp\View\AdminBansEmailView(
    email_addr: $email,
    email_js: $emailJs,
));
echo '</div></div>';
