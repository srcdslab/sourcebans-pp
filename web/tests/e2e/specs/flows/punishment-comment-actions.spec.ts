/**
 * Port of upstream sbpp/sourcebans-pp's `punishment-comment-actions.spec.ts`
 * (issue #1544 — every ban and comm block exposes Add comment, while
 * each existing comment exposes the author/owner-appropriate Edit /
 * Delete actions in both the desktop disclosure and the player
 * drawer), adapted to this fork's architecture.
 *
 * Upstream's version drives a dedicated `#banlist-comment-form` PAGE
 * (`row-action-comment-add` navigates to a standalone editor surface
 * built from their extracted `punishment-comment-editor.tpl` partial).
 * This fork never grew that partial — per `page_bans.tpl`'s own
 * docblock ("Add / Edit comments open the player drawer
 * (data-comment-compose); there is no `?comment=` editor on this
 * page"), comment add/edit is entirely drawer-driven:
 *
 *   - The banlist/commslist row's inline disclosure carries an
 *     "Add Comment" button (`[data-testid="ban-comment-add"]` /
 *     `[data-testid="comm-comment-add"]`) with `data-drawer-bid` /
 *     `data-drawer-cid` + `data-comment-compose="add"`. Clicking it
 *     opens the player drawer AND pre-opens the comment composer
 *     form in one step (`loadDrawer(key, {mode: 'add'})` ->
 *     `openCommentComposer()` in theme.js).
 *   - The composer is `[data-testid="drawer-comment-form"]` with a
 *     `textarea[name="ctext"]` and a `button[type="submit"]`; submit
 *     calls `bans.add_comment` / `bans.edit_comment` then reloads the
 *     drawer, which in turn patches the row's inline disclosure in
 *     place (no page navigation either way).
 *   - Existing comments in the disclosure carry an edit trigger
 *     (`[data-comment-compose="edit"][data-comment-cid="<cid>"]`,
 *     gated on `can_edit`) and a delete trigger
 *     (`[data-action="comment-delete"][data-cid="<cid>"]`, gated on
 *     `can_delete`) — both wired through the shared
 *     `comment-actions.js` dispatcher. The drawer's own comment list
 *     mirrors the same delete trigger plus a `[data-comment-edit]`
 *     attribute for its edit button.
 *
 * The contract this locks in is the same as upstream's: Add comment
 * is reachable from the row, the new comment round-trips into BOTH
 * the inline disclosure and the drawer, and both surfaces expose
 * Edit + Delete for a comment the logged-in admin (Owner storage
 * state) is allowed to act on.
 */

import { expect, test } from '../../fixtures/auth.ts';
import { expectNoCriticalA11y } from '../../fixtures/axe.ts';
import { seedBanViaApi, seedCommViaApi } from '../../fixtures/seeds.ts';

test.describe('flow: punishment comment actions (#1544)', () => {
    test('ban Add comment flow restores per-comment Edit and Delete', async ({ page, isMobile }, testInfo) => {
        test.skip(isMobile, 'inline disclosure assertions are desktop-only, matching page_bans.tpl');

        const seeded = await seedBanViaApi(page, {
            nickname: `e2e-ban-comment-actions-w${testInfo.workerIndex}-r${testInfo.retry}`,
            steam: `STEAM_0:1:${6_544_000 + testInfo.workerIndex * 100 + testInfo.retry}`,
            reason: 'e2e comment actions',
        });
        const comment = `ban comment action ${testInfo.workerIndex}`;

        await page.goto('/index.php?p=banlist');
        const row = page.locator(`[data-testid="ban-row"][data-id="${seeded.bid}"]`);
        const disclosure = row.locator('[data-testid="ban-comments-inline"]');
        await disclosure.locator('[data-testid="ban-comments-toggle"]').click();

        const addBtn = disclosure.locator('[data-testid="ban-comment-add"]');
        await expect(addBtn).toBeVisible();
        await addBtn.click();

        const drawer = page.locator('#drawer-root');
        await expect(drawer).toHaveAttribute('data-drawer-open', 'true');
        await expect(drawer).not.toHaveAttribute('data-loading', /.+/);

        const composer = drawer.locator('[data-testid="drawer-comment-form"]');
        await expect(composer).toBeVisible();
        await expectNoCriticalA11y(page, testInfo, { include: ['#drawer-root'] });
        await composer.locator('textarea[name="ctext"]').fill(comment);

        const addResponsePromise = page.waitForResponse(
            (response) =>
                response.url().includes('api.php')
                && response.request().method() === 'POST'
                && response.status() === 200,
        );
        await composer.locator('button[type="submit"]').click();
        const addEnvelope = await (await addResponsePromise).json();
        expect(addEnvelope.ok, `bans.add_comment must succeed: ${JSON.stringify(addEnvelope)}`).toBe(
            true,
        );

        // The drawer reload patches the row's inline disclosure in place —
        // no navigation, so re-query the same locators rather than reload.
        const inlineText = disclosure.locator('[data-testid="ban-comment-text"]');
        await expect(inlineText).toContainText(comment);
        const inlineItem = disclosure.locator('[data-testid="ban-comment-item"]').filter({ hasText: comment });
        await expect(inlineItem.locator('[data-comment-compose="edit"]')).toBeVisible();
        await expect(inlineItem.locator('[data-action="comment-delete"]')).toBeVisible();

        const drawerComments = drawer.locator('[data-testid="drawer-comments"]');
        await expect(drawerComments).toContainText(comment);
        const drawerItem = drawerComments.locator('li').filter({ hasText: comment });
        await expect(drawerItem.locator('[data-comment-edit]')).toBeVisible();
        await expect(drawerItem.locator('[data-action="comment-delete"]')).toBeVisible();
        await expectNoCriticalA11y(page, testInfo, { include: ['#drawer-root'] });
    });

    test('comm-block Add comment uses the shared drawer composer and action set', async ({ page, isMobile }, testInfo) => {
        test.skip(isMobile, 'inline disclosure assertions are desktop-only, matching page_comms.tpl');

        const seeded = await seedCommViaApi(page, {
            nickname: `e2e-comm-comment-actions-w${testInfo.workerIndex}-r${testInfo.retry}`,
            steam: `STEAM_0:0:${6_544_100 + testInfo.workerIndex * 100 + testInfo.retry}`,
            reason: 'e2e comm comment actions',
            type: 1,
        });
        const comment = `comm comment action ${testInfo.workerIndex}`;

        await page.goto('/index.php?p=commslist');
        const row = page.locator('[data-testid="comm-row"]').filter({ hasText: seeded.steam });
        const cid = Number(await row.getAttribute('data-id'));
        expect(cid).toBeGreaterThan(0);

        const disclosure = row.locator('[data-testid="comm-comments-inline"]');
        await disclosure.locator('[data-testid="comm-comments-toggle"]').click();

        const addBtn = disclosure.locator('[data-testid="comm-comment-add"]');
        await expect(addBtn).toBeVisible();
        await addBtn.click();

        const drawer = page.locator('#drawer-root');
        await expect(drawer).toHaveAttribute('data-drawer-open', 'true');
        await expect(drawer).not.toHaveAttribute('data-loading', /.+/);

        const composer = drawer.locator('[data-testid="drawer-comment-form"]');
        await expect(composer).toBeVisible();
        await expectNoCriticalA11y(page, testInfo, { include: ['#drawer-root'] });
        await composer.locator('textarea[name="ctext"]').fill(comment);

        const addResponsePromise = page.waitForResponse(
            (response) =>
                response.url().includes('api.php')
                && response.request().method() === 'POST'
                && response.status() === 200,
        );
        await composer.locator('button[type="submit"]').click();
        const addEnvelope = await (await addResponsePromise).json();
        // Same bans.add_comment action as the ban-focal test above — the
        // drawer composer reuses it for comm-block comments too, keyed by
        // the `ctype: 'C'` param (see submitCommentForm in theme.js).
        expect(addEnvelope.ok, `bans.add_comment (ctype=C) must succeed: ${JSON.stringify(addEnvelope)}`).toBe(
            true,
        );

        const inlineText = disclosure.locator('[data-testid="comm-comment-text"]');
        await expect(inlineText).toContainText(comment);
        const inlineItem = disclosure.locator('[data-testid="comm-comment-item"]').filter({ hasText: comment });
        await expect(inlineItem.locator('[data-comment-compose="edit"]')).toBeVisible();
        await expect(inlineItem.locator('[data-action="comment-delete"]')).toBeVisible();

        const drawerComments = drawer.locator('[data-testid="drawer-comments"]');
        await expect(drawerComments).toContainText(comment);
        const drawerItem = drawerComments.locator('li').filter({ hasText: comment });
        await expect(drawerItem.locator('[data-comment-edit]')).toBeVisible();
        await expect(drawerItem.locator('[data-action="comment-delete"]')).toBeVisible();
        await expectNoCriticalA11y(page, testInfo, { include: ['#drawer-root'] });
    });
});
