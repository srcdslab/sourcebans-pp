<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.
//
// Endpoints used by the admin.blockit.php iframe.

use SteamID\SteamID;

function api_blockit_load_servers(array $params): array
{
    $servers = $GLOBALS['PDO']
        ->query("SELECT sid, rcon FROM `:prefix_servers` WHERE enabled = 1 ORDER BY modid, sid")
        ->resultset();

    $out = [];
    $id  = 0;
    foreach ($servers as $s) {
        $out[] = [
            'num'      => $id,
            'sid'      => (int)$s['sid'],
            'has_rcon' => !empty($s['rcon']),
        ];
        $id++;
    }
    return ['servers' => $out];
}

function api_blockit_block_player(array $params): array
{
    $check  = (string)($params['check']  ?? '');
    $sid    = (int)($params['sid']    ?? 0);
    $num    = (int)($params['num']    ?? 0);
    $type   = (int)($params['type']   ?? 0);
    $length = (int)($params['length'] ?? 0);

    // #1423 follow-up #4 — gate `$check` shape BEFORE the
    // `SteamID::compare()` call below; the comms-block flow is always
    // Steam-ID-keyed (there is no "block by IP" path) so the gate is
    // unconditional. `compare()` routes through `toSteam64()` which
    // throws on any non-isValidID input; without this gate a hostile
    // caller posting `?check=garbage` 500s the handler instead of
    // getting the `not_found` envelope the iframe loop expects.
    if (!SteamID::isValidID($check)) {
        return [
            'status'   => 'not_found',
            'sid'      => $sid,
            'num'      => $num,
            'hostname' => '',
            'ip'       => '',
            'port'     => '',
        ];
    }

    // Blocking is an RCON action: it needs the per-server mapping, like
    // kickit.kick_player. The one exception is the fan-out that follows
    // comms.add, which applies a just-added block on every server because
    // the block itself is global. The exception only applies when the
    // target really has an active block of that type; otherwise this
    // action would gag or mute anyone on any server.
    if (!_api_servers_caller_can_rcon($sid) && !_api_blockit_target_has_active_block($type, $check)) {
        _api_servers_require_rcon_access($sid, 'block a player');
    }

    $serverInfo = $GLOBALS['PDO']->query("SELECT ip, port FROM `:prefix_servers` WHERE sid = :sid");
    $GLOBALS['PDO']->bind(':sid', $sid);
    $sdata = $GLOBALS['PDO']->single() ?: ['ip' => '', 'port' => ''];

    $ret = rcon('status', $sid);
    if (!$ret) {
        return [
            'status'   => 'no_connect',
            'sid'      => $sid,
            'num'      => $num,
            'hostname' => '',
            'ip'       => $sdata['ip'],
            'port'     => $sdata['port'],
        ];
    }

    if (preg_match('/hostname:[ ]*(.+)/', $ret, $hostname)) {
        $hostname = trunc(htmlspecialchars($hostname[1]), 25);
    } else {
        $hostname = '';
    }

    foreach (parseRconStatus($ret) as $player) {
        if (SteamID::compare($player['steamid'], $check)) {
            $GLOBALS['PDO']->query("UPDATE `:prefix_comms` SET sid = :sid WHERE authid = :authid AND RemovedBy IS NULL");
            $GLOBALS['PDO']->bind(':sid', $sid);
            $GLOBALS['PDO']->bind(':authid', $check);
            $GLOBALS['PDO']->execute();

            rcon("sc_fw_block $type $length {$player['steamid']}", $sid);

            return ['status' => 'blocked', 'sid' => $sid, 'num' => $num, 'hostname' => $hostname, 'ip' => $sdata['ip'], 'port' => $sdata['port']];
        }
    }

    return ['status' => 'not_found', 'sid' => $sid, 'num' => $num, 'hostname' => $hostname, 'ip' => $sdata['ip'], 'port' => $sdata['port']];
}

/**
 * True when `$check` (a validated SteamID) has an active, unlifted block
 * covering `$type` (1 = mute, 2 = gag, 3 = both). comms.add stores a
 * silence as one mute row plus one gag row; forks and imports may store
 * it as a single type 3 row, which covers every type.
 */
function _api_blockit_target_has_active_block(int $type, string $check): bool
{
    $rows = $GLOBALS['PDO']->query(
        "SELECT DISTINCT type FROM `:prefix_comms`
          WHERE authid IN (?, ?) AND RemovedBy IS NULL AND RemoveType IS NULL
            AND (length = 0 OR ends > UNIX_TIMESTAMP())"
    )->resultset(_api_servers_steam2_forms(SteamID::toSteam2($check)));
    $types = array_map(static fn (array $r): int => (int) $r['type'], $rows);

    if (in_array(3, $types, true)) {
        return true;
    }
    return match ($type) {
        1 => in_array(1, $types, true),
        2 => in_array(2, $types, true),
        3 => in_array(1, $types, true) && in_array(2, $types, true),
        default => false,
    };
}
