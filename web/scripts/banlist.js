// @ts-check
/* ============================================================
   banlist.js — public ban list interactions

   Layered on top of the server-rendered table from
   themes/default/page_bans.tpl. The template is fully usable
   without this script (filters fall through as a server-side
   ?searchText= query, copy buttons no-op), so this file only
   keeps the loading-skeleton hook on `#banlist-root`.

   Add / Edit comments live in the player drawer (`theme.js`)
   and on queue cards (`comment-actions.js`). There is no
   `#banlist-comment-form` page editor.

   The status-filter chips are server-rendered anchors (#1352).
   Pre-#1352 this file owned a `applyStateFilter` row-hide layer
   (chip click → loop `.ban-row[data-state]`, flip
   `display:none` on rows whose `data-state` didn't match) that
   only operated on the rowset the server already returned —
   so a 10k-ban install where 50 rows were unbanned would still
   render 30 invisible rows on page 1 of `?state=unbanned` and
   the chip read as broken. The new chip strip in `page_bans.tpl`
   is real anchors that navigate to `?p=banlist&state=<slug>`,
   the page handler narrows the SQL rowset, and pagination /
   no-JS browsers / shared deep links all behave correctly.
   See "Server-side state filter" in `page.banlist.php` for the
   full predicate set.

   The SteamID copy buttons in the row-actions cell are wired by
   theme.js's document-level `[data-copy]` click delegate (single
   source for every copy affordance on the panel — banlist row,
   drawer identity rows, future surfaces). Pre-#1308 this file's
   docblock claimed it owned that wiring; it never did, and the
   inline `onclick="event.stopPropagation()"` on the button
   silently killed the document delegate on the bubble phase.
   Both halves are fixed in #1308 — the wiring stays in theme.js.
   ============================================================ */
(function () {
  'use strict';

  /** @type {HTMLElement | null} */
  const root = /** @type {HTMLElement | null} */ (document.getElementById('banlist-root'));

  // ---- LOADING SKELETON HOOK -------------------------------
  // The chip filter is now a server-rendered anchor (#1352) so
  // there's no client-side row-hide work for the skeleton hook
  // to gate. Reserved for future C-phase async fetches (e.g.
  // the drawer detail load). Kept as a no-op API on the root so
  // the marquee testability contract is satisfied.
  if (root) {
    /** @type {any} */ (root).sbpp_setLoading = (/** @type {boolean} */ flag) => {
      root.dataset.loading = flag ? 'true' : 'false';
    };
  }
})();
