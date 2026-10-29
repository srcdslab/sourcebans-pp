SourceBans++ Change Log
============

```
Legend:
* = New feature
- = Removed stuff
+ = Improved feature
! = Fixed bug
? = Other stuff
```

(29/10/26): Version 2.2.10-srcdslab
-----------------------
```
01. + sbpp_main no longer re-sets the database charset (a blocking
        round trip on the main thread) on every admin cache rebuild;
        it is set once per connection

(29/10/26): Version 2.2.9-srcdslab
-----------------------
```
01. ! CI: the Docker image workflow failed on every push to main since
        the Actions bump; cosign-installer is now pinned to v4.1.2
02. ? E2E: the "bulk select → assign web group" test no longer races
        the page reload that follows the bulk action
```

(29/10/26): Version 2.2.8-srcdslab
-----------------------
```
01. ! Ban list: the server and time filters (and the status chips /
        Hide inactive) did nothing after clicking Apply; the search
        clauses now wrap in parentheses so every filter applies
02. ! Comm blocks list: the server and time filters were never applied
        to the query; they now narrow the list and survive pagination
03. ! Comm blocks list: Hide inactive combined with an advanced search
        the viewer can't run no longer fails with a SQL error
```

(28/10/26): Version 2.2.7-srcdslab
-----------------------
```
01. ! sbpp_comms: mutes / gags queued while the database was
        unreachable were replayed against the local SQLite queue
        instead of the main database, so they stayed queued and never
        reached the web panel
02. + sbpp_comms keeps its database connection across map changes
        instead of reconnecting (and re-checking every player) on
        each map; a plain SQL error or a failed SQLite queue query no
        longer drops the main connection
03. + SteamID lookups on player connect (bans, comms, SourceSleuth,
        Bans Checker) and admin lookups no longer use REGEXP / LIKE,
        so MySQL can use the authid indexes instead of a full scan
04. ! sbpp_main, sbpp_checker and SourceSleuth retry a failed database
        connection on a timer; sbpp_checker no longer unloads itself
        and checks the players who joined while it was disconnected,
        and sm_banip / sm_unban / sm_addban / reports reply with an
        error instead of throwing when the database is unavailable
```

(26/10/26): Version 2.2.5-srcdslab (**Run updater required**)
-----------------------
```
01. ! Players who joined before the database connected, hit a failed
        ban query, or were online when sbpp_main late-loaded were never
        checked for bans; the retry timer now re-queries
02. ! Steam Networking (SDR / FakeIP) players: the shared 169.254.x.x
        placeholder is no longer stored or matched as their IP; sm_banip
        refuses them, SourceSleuth skips them, and updater migration
        816 cleans placeholders stored by older plugins
03. ! SourceSleuth no longer re-bans a player on their own ban (with
        sm_sleuth_actions 3 the length doubled on every reconnect)
```

(26/10/26): Version 2.2.4-srcdslab
-----------------------
```
01. + Telemetry sends the fields the analytics Worker expects: shared-
        hosting environment signals, 30-day activity, game mix,
        permission shape, data-export usage and the continent of the
        panel's timezone (still no hostnames, IPs, names or SteamIDs)
02. ? The Docker dev / CI stack no longer sends telemetry pings
```

(26/10/26): Version 2.2.3-srcdslab (**Run updater required**)
-----------------------
```
01. ! Upgraded installs missing the type_authid / type_ip indexes on
        sb_bans get them back (updater migration 815); the ban check,
        banlist and PruneBans() no longer scan the whole table there
```

(26/10/26): Version 2.2.2-srcdslab
-----------------------
```
01. ! Security: uploaded demos can no longer be fetched directly from
        /demos/; getdemo.php is the only download path (Apache rules
        in the Docker images + a shipped demos/.htaccess for tarball
        installs, nginx / IIS rules in the quickstart docs)
02. ! Security: uploaded demos are named from a CSPRNG instead of
        md5(SteamID . time())
03. ! Security: every response sends X-Content-Type-Options: nosniff
04. ! Dev stack: demos/ is writable by the web container
```

(26/10/26): Version 2.2.1-srcdslab
-----------------------
```
01. ! Security: password reset mails go to the address stored on the
        admin row, never to a case- or accent-variant of it typed in
        the form; the reset token is rolled by admin id
02. ! Security: the reset token is compared byte-exact (hash_equals)
```

(22/10/26): Version 2.1.26-srcdslab
-----------------------
```
01. ! sm_comms on a player without a mute or gag replied with a
        missing-phrase error (CommandComms_nc added to sbpp_comms)
02. ! German comms time help showed "\.n" instead of a line break
```

(22/10/26): Version 2.1.25-srcdslab
-----------------------
```
01. ? Dependabot no longer assigns the upstream maintainers to this
        fork's dependency PRs
```

(21/10/26): Version 2.1.23-srcdslab
-----------------------
```
01. ! Security: the production Docker image refuses to build on PHP
        below 8.5.12 (CVE-2026-109618, CVE-2026-109619, unauthenticated
        RCE) and always pulls a fresh php:8.5 base image
02. ! Security: production php.ini disables session upload progress and
        fatal error backtraces (CVE-2026-109619 hardening)
03. + Install wizard warns when PHP is older than 8.5.12
```

(20/10/26): Version 2.1.22-srcdslab
-----------------------
```
01. + Player drawer: the SteamID, Steam3 and Community values link to
        the player's Steam Community profile
02. ? Default theme version 2.0.4
```

(20/10/26): Version 2.1.21-srcdslab
-----------------------
```
01. ! Comm blocks list: after deleting a block, the next Remove no
        longer opens the "Delete block" dialog with its confirm button
        stuck on the spinner (#51)
02. ? Default theme version 2.0.3
```

(20/10/26): Version 2.1.20-srcdslab
-----------------------
```
01. ! Password reset emails now link to the right place on panels
        installed in a subfolder (the reset link used to 404) (#71)
02. ! "Ban added", contact and SMTP test emails keep the install
        subfolder in their panel links (#71)
```

(20/10/26): Version 2.1.19-srcdslab
-----------------------
```
01. * The ban list shows the player's country flag again, in place of
        the initials avatar; the player drawer shows the flag and the
        country name (#49)
02. + Settings > Main: the toggle now reads "Show player country
        flags" (same `banlist.nocountryfetch` key, no migration) (#49)
03. ! Security: the stored country code is validated against the
        bundled flags before it reaches the page (#49)
04. ? Default theme version 2.0.2
```

(20/10/26): Version 2.1.18-srcdslab (**Run updater required**)
-----------------------
> [!IMPORTANT]
> Every admin is logged out once after this upgrade.
```
01. ! Security: session cookies now expire server-side (`exp` / `nbf`
        are validated) instead of staying valid forever (#54)
02. ! Security: sessions are stored in `:prefix_login_tokens`; logout
        revokes the session on the server (#54)
03. + Changing or resetting a password, deactivating or deleting an
        admin ends every session of that admin (#54)
04. ! A cookie for a deleted or deactivated admin no longer counts as
        logged in (#54)
05. ? Updater migration 814 adds `:prefix_login_tokens.aid`
```

(20/10/26): Version 2.1.17-srcdslab
-----------------------
```
01. ! Security: notification emails HTML-escape every template value, so
        text from the public Submit / Protest forms can no longer inject
        links or images into admin inboxes (#56)
02. ! Custom themes' `mails/*.html` templates are used again; themes
        without them fall back to the default theme instead of failing
        every send (#56)
```

(20/10/26): Version 2.1.16-srcdslab
-----------------------
```
01. ! Protest a ban: SteamID64, [U:1:N] and STEAM_1 IDs now find the ban
        instead of "That Steam ID is not banned!" (#58)
02. ! Protest a ban: an archived protest no longer blocks every future
        appeal; the protest attaches to the newest active ban (#58)
03. ! Submit a ban: IP-only reports are no longer rejected because a
        permanent IP ban exists; the permanent-ban check matches every
        Steam ID format (#58)
04. ! Submission email: the Steam ID is filled in (was always "NA") and
        the demo / queue links use the right scheme and subfolder (#58)
```

(20/10/26): Version 2.1.15-srcdslab
-----------------------
```
01. ! Security: admins with only "Edit own bans" or "Edit group bans"
        could edit every comm block (inverted check) (#55)
02. ! Security: submission demos (`getdemo.php?type=S`) now require
        ADMIN_BAN_SUBMISSIONS; ban demos stay public (#55)
03. ! Security: the contact page (`?p=admin&c=bans&o=email`) requires
        the submissions / protests flag before showing a reporter's
        email (#55)
04. ! The group editor requires ADMIN_EDIT_GROUPS (#55)
05. + Admins with "Edit group bans" can reach comm block edits, like
        ban edits (#55)
```

(20/10/26): Version 2.1.14-srcdslab
-----------------------
```
01. ! Security: `bans.send_message` no longer lets any web admin run
        arbitrary RCON. It now requires ADMIN_ADD_BAN plus per-server
        access, and control characters are stripped from the message (#53)
02. ! Security: `bans.view_community`, `bans.setup_ban`,
        `bans.prepare_reban`, `comms.prepare_reblock` and
        `comms.prepare_block_from_ban` now require ADMIN_ADD_BAN (#53)
```

(20/10/26): Version 2.1.13-srcdslab
-----------------------
```
01. ! Security: the ban / comm list GET-fallback key is now CSPRNG-minted
        (256 bits) and checked with hash_equals; an empty `key=` no
        longer passes on a session that never opened a list page (#57)
```

(20/10/26): Version 2.1.12-srcdslab
-----------------------
```
01. ! Security: the login form no longer reveals whether a username
        exists (same answer for an empty password, same bcrypt delay
        for unknown users) (#59)
```

(20/10/26): Version 2.1.11-srcdslab
-----------------------
```
01. ! Moderation queue: the submission "Get demo" link shows its icon
        (Lucide instead of the missing Font Awesome); "No demo" is plain
        text instead of a dead link (#60)
02. ! `exportbans.php` serves `banned_user.cfg` / `banned_ip.cfg` as
        text/plain, returns 400 for an unknown type and 403 when access
        is denied (#60)
```

(19/10/26): Version 2.1.10-srcdslab
-----------------------
```
01. + Ban list and comms list: repeat offenders get a history chip next
        to their name with the number of punishments on record (bans, or
        mutes, gags and silences). Click it to list them all
```

(05/05/26): Version 2.0.0 (**Run updater required**)
-----------------------
> [!IMPORTANT]
> Major release. The default theme is rebuilt from the ground up.
> Custom themes that forked the pre-2.0 default keep working but
> render in a compatibility mode; see the migration notes in the
> release for details.
>
> **The web panel licence has changed** from CC BY-NC-SA 3.0 to the
> Elastic License 2.0. Hobby / community self-hosting stays free
> (most operators see no operational change). Offering SourceBans++
> to third parties as a hosted or managed service is now reserved
> by ELv2 and needs a separate commercial licence. SourceMod
> plugins remain GPLv3. Full breakdown:
> [Upgrading 1.8 → 2.0 — Licence change](https://sbpp.github.io/updating/1-8-to-2-0/#licence-change).
```
01. * Rebuilt default theme: drawer-based admin nav, command palette
        (Ctrl/Cmd-K), light/dark/system theming, accessibility-first
        form controls, design-system tokens
02. * Public ban list redesign: marquee row layout, status-filter
        chips, SteamID copy buttons, right-side player drawer
03. * Public dashboard, comms list, servers card grid, login,
        lost-password, submit-ban and protest-ban forms all rebuilt
04. * Admin home card-grid landing
05. * Admin audit log page (drives off the existing :prefix_log table)
06. * `bans.detail` JSON action — payload for the public ban-row drawer
07. * `bans.search` JSON action — autocomplete backend for the command
        palette
08. * Markdown rendering for the dashboard intro (`dash.intro.text`)
        via league/commonmark + `Sbpp\Markup\IntroRenderer` (CommonMark
        with `html_input: 'escape'`, no unsafe links, no JS execution)
09. * Typed View DTOs (`Sbpp\View\*`) for every panel template, with
        a custom PHPStan rule that cross-checks template variables
        against View properties
10. * `Sbpp\View\Perms::for($userbank)` permission helper + the
        `{has_access flags=…}` Smarty block plugin
11. * Autogenerated JavaScript API contract (`Actions.*` + `Perms.*`)
        produced by `web/bin/generate-api-contract.php`; CI fails on
        diff
12. * Snapshot-tested JSON API responses (`tests/api/__snapshots__/`)
        and an action-to-permission matrix lock
        (`PermissionMatrixTest`)
13. * Configurable SMTP `From Email` / `From Name` (#1109)
14. * Local Docker dev stack (PHP 8.5 + Apache, MariaDB, Adminer,
        Mailpit) driven by `./sbpp.sh`
15. * Static analysis: PHPStan level 5 + custom Smarty rule +
        staabm/phpstan-dba SQL type-checking against the live schema
16. * `tsc --checkJs` over `web/scripts/` with `// @ts-check` +
        JSDoc throughout
17. + Replaced xajax with a JSON API (`api.php` + `api/handlers/*.php`)
18. + Finished ADOdb -> PDO migration (`Database` wrapper with
        `:prefix_` rewriting); ADOdb dependency dropped entirely
19. + CSRF protection on every state-changing form / JSON call
20. + Smarty global escape-by-default; explicit `nofilter` annotations
        with mandatory `{* nofilter: <reason> *}` comments
21. + URL-encode user-controlled values in generated hrefs (#1085)
22. + Stream `exportbans.php` rows instead of buffering the full
        result (#1093)
23. + Search now matches both `STEAM_0:` and `STEAM_1:` stored authid
        variants (#1130)
24. + `utf8mb4` end-to-end (panel PDO + plugin `SET NAMES`); rejects
        the 3-byte `utf8` alias (#1108)
25. - Removed `web/scripts/sourcebans.js` (~1.7k-line MooTools-flavoured
        bulk file); per-page tail scripts are now self-contained
        vanilla JS
26. - Removed TinyMCE WYSIWYG for `dash.intro.text` (it was the
        stored-XSS vector behind #1113); replaced with a plain
        `<textarea>` + Markdown
27. - Removed xajax (`sb-callback.php`) and the legacy callback
        contracts that depended on it
28. - Removed ADOdb library
29. ! XSS via `dash.intro.text` rendered raw through `nofilter`
        (#1113)
30. ! Stored-XSS / unescaped HTML through Smarty templates that
        omitted explicit escape (audited as part of the global
        escape-by-default flip)
31. ! Email injection on legacy mail flows tightened by Symfony
        Mailer
32. ! Gated normal-login flow on its own `config.enablenormallogin`
        setting (#1102)
33. ? PHP 8.5 minimum (was 8.2); Smarty 5; lcobucci/jwt for the
        auth cookie; league/commonmark for admin Markdown (#1289
        bumped the floor pre-tag)
34. ? `web/themes/default/` is the new default theme; the previous
        default ships as a compatibility shape (legacy property
        names, alias keys) so third-party themes that forked it
        keep rendering off the same View DTOs
35. ? Documentation overhaul: `ARCHITECTURE.md` (codebase tour) +
        `AGENTS.md` (workflow / conventions) live alongside
        `README.md`; user-facing install / upgrade / configure
        guides moved to the Starlight site at sbpp.github.io
36. • SourceMod native API epoch: `MAJOR_REVISION` / `MINOR_REVISION` and
        `SB_VERSION` live in generated `include/sbpp_version.inc`
        (`scripts/resolve-plugin-version.sh` — release CI tag via
        `SBPP_RELEASE_VERSION`, then `configs/version.json` →
        `git describe` → `dev` like the panel; `MINOR_REVISION` is the
        native API additive counter, not panel semver minor). Direct
        `spcomp` builds use the checked-in `dev` fallback or run the
        script locally. New `SOURCEBANSPP_VERSION_MAJOR` for optional
        compile-time guards. Third-party plugins need a rebuild only when
        they use checker library
        detection (`"sourcechecker++"`, not `"sourcebans++"` — #1034), new
        checker mute/gag natives (#1032), or hook
        `SBPP_OnClientPostAdminCheck` (#1431). Plugins that only call
        existing SBPP ban/report forwards/natives can usually keep their
        existing `.smx`. ([#1114](https://github.com/sbpp/sourcebans-pp/issues/1114))
```

### Privacy

This release ships **default-on anonymous telemetry** (#1126). Once per
day per install, the panel sends a small JSON payload to a SourceBans++
Cloudflare Worker so maintainers can see what versions, environments,
and feature toggles are actually in use. The payload is random
per-install ID + categorical / count fields only — **no** hostnames,
IPs, admin names, SteamIDs, ban reasons, or any other PII. The toggle
lives at **Admin → Settings → Features → Privacy → Anonymous telemetry**;
disabling it clears the per-install ID so re-enabling later issues a
fresh one. The complete field list lives in the code at
[`web/includes/Telemetry/schema-1.lock.json`](web/includes/Telemetry/schema-1.lock.json);
the upgrade-time disclosure (and self-hosted-collector escape hatch)
lives on the docs site at
[Upgrading from 1.8.x to 2.0.x](https://sbpp.github.io/updating/1-8-to-2-0/#anonymous-telemetry).
Companion Worker repo: [sbpp/cf-analytics](https://github.com/sbpp/cf-analytics).

(10/11/24): Version 1.8.1 (**Run updater required**)
-----------------------
> [!IMPORTANT]
> This is a security release and we recommend to upgrade as soon as possible.
```
01. ! XAJAX API 'Plogin' Vulnerable to Brute Force Attacks
02. ! XAJAX API 'Plogin' can bypass disabled 'Enable Normal Login'
03. ! Vulnerability in Forgot Password implementation
04. * Locking account for 10 minutes if wrong password multiple times (x5)
05. ! Verify if user is already logged before display login page
06. ! Ignore chat triggers for interactive ban reason
07. * Checker: configure client connect message output
08. ! Support new line in comments
09. ? CI: Build with latest SM 1.12 stable version
10. ! Tab navigation logic and validation in admin panel
11. + Extend input compatibility to all steam id formats
12. ? Bump Font Awesome to 6.6.0
13. ! Do not print unblock infos if block still active
14. ! Prevent empty name on dashboard
15. ! Clean player names of unwanted chars
```

(18/02/23): Version 1.8.0
-----------------------
```
01. ? Add PHP 8.1 Compatibility
02. ? Update dependencies
03. ? Update requirements to PHP 8.1
04. ? Update requirements to SM 1.11
05. ? Rename Checker natives
06. ! Fixed display in Admin Panel
07. * Add Board Name support
08. ! Fixed Display in Installer
09. ? Emails changes (SMTP/Email templates)
10. * Auto Add server with rcon password
10. ! Fixed permissions for ADMIN_EDIT_ADMINS to changes admins pw
11. ! Fixed a way to insert invalid SteamID Format in DB
12. ? Improve game translations
13. + Improved sm_banip
```

(26/09/22): Version 1.7.0
-----------------------
```
01. * Comms in count list
02. ? Update requirements to SM 1.10
03. ! Fixed issue with Data Pack
04. ! Fixed display in Admin Panel
```

(06/10/21): Version 1.6.4
-----------------------
```
01. * Support challenges in A2S_INFO
02. ! Fixed security vulnerability in the SetupEditServer
03. ! Fixed auth check
```

(06/04/18): Version 1.6.3
-----------------------
```
Full Changelog: https://sbpp.github.io/blog/1.6.3_release/
```

(04/07/17): Version 1.6.2
-----------------------
```
01. ! Fixed issue with group Banning
02. ! Fixed AmxBans import issue
03. ! Fixed possible XSS Injection
04. + Adjusted regex for CSGO
05. + Added option to disable 'comms' tab
06. ! Fixed bugs with SteamID format
07. ! Fixed version checks
08. ? Git version is now only shown in dev builds
09. ! Fixed issue with email links
10. * Added session based logins
```

(07/05/17): Version 1.6.1
-----------------------
```
01. ! Fixed an issue while XAJAX initialized
02. ! Fixed the 'dash intro text' not displaying custom HTML elements
03. ! Fixed 'change password' function
04. ! Fixed encoding issues with player names
05. ! Fixed aspect ratio of map image
06. ! Fixed editing groups/override pages
07. ! Fixed display error for 'edit mod' page
08. ! Fixed version numbering displaying 0
09. + Improved sizes and file types of images
```

(23/04/17): Version 1.6.0
-----------------------
```
01. ! Fixed some XSS exploits
02. + Improved password hashing / security
03. * Added utf8mb4 support
04. + Updated tinymce
05. + Reformatted most of the code
06. * Added new natives (SourceBans_OnBanPlayer, SourceComms_OnBlockAdded)
07. - Removed DB Info page (potential attack vector)
08. ! various Plugin fixes
09. + Updated Installer Theme
```

(28/04/16): Version 1.5.4.7
-----------------------
```
01. ! Fix Admins and Groups Not Loading from Config
```

(23/04/16): Version 1.5.4.6
-----------------------
```
01. ! Fix Perm Ban bug in SourceSleuth
02. ! Fix Updater
```

(18/04/16): Version 1.5.4.5
-----------------------
```
01. ! Fix Variuous Bugs in the Plugins EXCEPT SourceSleuth
02. ? Updated ADOdb and LightOpenID Library
```

(07/04/16): Version 1.5.4.4
-----------------------
```
01. ! Fix Memory Leak in SourceSleuth Plugin
02. ? Optimized and updated IpToCountry.csv
```

(24/03/16): Version 1.5.4.3
-----------------------
```
01. ! Downgrade plugin to 1.5.3
02. + Add ULX Module for GMOD (Not Maintained by Me)
```

(09/03/16): Version 1.5.4.2
-----------------------
```
01. ! Fix XSS Vulnerability in SourceComms Page
```

(01/03/16): Version 1.5.4.1
-----------------------
```
01. ! Fix Ban/Comm Reason Issue in Plugin
02. ? CC-BY-NC-SA-3.0
```

(14/02/16): Version 1.5.4
-----------------------
```
01. * Added Steam3 ID to Ban and Comm list
02. * Added PHP7 Support
03. + Updated Comms page with better CSS
04. + Small misc theme fixes
05. + Small plugin fixes/optimizations
06. ! Fixed config.php bug with APIKey and URL
07. ! Fix MariaDB Empty Ban List
08. ? Optimized and updated IpToCountry.csv
```

(01/09/15): Version 1.5.3
-----------------------
```
01. * Added Steam API Key to Installer for Future Use
02. * Added Steam OpenID Login Support
03. * Added Updater Support
04. * Added Own Admin Config System (No More admins.cfg)
05. + Updated Smarty Library to 2.6.29
06. + Updated Plugins to use partial SourceMod 1.7 Syntax/API
07. + Changed Webpanel Background Color
08. ! Fixed Email Injection Bug on Webpanel
09. ! Fixed admin-flatfile issue in TF2 with New Config System
10. ! Fixed RCON on webpanel skipping NULL characters (RCON XML error)
11. ! Fixed importing banned_user.cfg with Steam3 [U:1:X]
12. ! Fixed BoxToMask Issue #52 in SourceBans.js
13. ! Fix HHVM issues with ADOdb
14. ? Optimized and updated IpToCountry.csv
```

(29/05/15): Version 1.5.2F
-----------------------
```
01. * Changed licence to GNU AGPL v3
02. * Replaced GetClientAuthString with GetClientAuthId for SourceMod 1.7
03. * Added IP Banning with SourceSleuth
04. + Updated ADOdb Library to 5.19
05. + Updated TinyMCE Library to 3.5.11
06. - SourceMod 1.6.x and below are not supported
07. - Removed FamilySharing Ban Evasion Detection
08. - MariaDB not does not work anymore (Never was supported anyways)
09. ! Fixed Ban List lagging on MySQL 5.6+
10. ! Fixed Plugin Showing DataPack error
11. ! Fixed KickId in Webpanel not working when trying to use Steam3
12. ? Optimized and updated IpToCountry.csv
```

(29/01/15): Version 1.5.1F
-----------------------
```
01. * Changed licence to GNU GPL v3
02. * Added SourceBans Connection Debugger
03. * Added SourceComms Search Box
04. + Re-made SourceBans Logo in Footer
05. ! Fixed getdemo.php spewing errors
06. ! Fixed Invalid Query in SB Plugin
07. ! Fixed parsing rcon status in CS:GO
08. ? Added/Fixed Copyright Headers
09. ? Updated SteamWorks Ext to git90
10. ? Optimized and updated IpToCountry.csv
```

(26/12/14): Version 1.5.0F
-----------------------
```
01. * Integrated SourceComms
02. * Added TF2 Modern Theme as Default (Made by IceMan)
03. * Integrated SourceBans Checker
04. * Re-made SourceBans FAQ
05. * Added MvM and HL2 Map Pics
06. * Added Synergy to the Game List
07. + Re-arranged/Renamed Tabs
08. + Added More Robust LFI Patch
09. ! Fixed Plugin Pointing to wrong FAQ link
10. ? Optimized and updated IpToCountry.csv
```

(02/12/14): Version 1.4.13F
-----------------------
```
01. ! Fixed LFI EXPLOIT //Thanks jsifuentes
02. ? Optimized and updated IpToCountry.csv
```

(15/11/14): Version 1.4.12F
-----------------------
```
01. * Added Steam3 Support for Player Menu
02. * Added IP Ban checking from SourceSlueth
03. ! Fixed Steam Family Sharing Ban Evasion.
04. ? Added SteamWorks Extension
05. ? Optimized and updated IpToCountry.csv
```
