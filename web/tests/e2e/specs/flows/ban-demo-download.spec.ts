/**
 * Port of upstream sbpp/sourcebans-pp's `ban-demo-download.spec.ts`
 * (issue #1554, already carried on this fork by `fix/issue-1554` /
 * PR #26 — the drawer's "Download demo" affordance itself). Upstream
 * added E2E coverage for that surface which this fork didn't have a
 * matching spec for; this ports it, adapted to seed the demo through
 * the `seed-ban-demo-e2e.php` shim (`seedBanDemoE2e`) instead of
 * writing straight into `../../demos` from Node — this suite runs in
 * two modes (`E2E_IN_CONTAINER=1` inside the web container, or
 * host-side via `docker compose exec`), and only the PHP side
 * reliably resolves `SB_DEMOS` the same way `getdemo.php` does in
 * both modes.
 *
 * What this locks in
 * ------------------
 * Ban evidence downloads must be reachable from BOTH the banlist row
 * (`[data-testid="row-action-demo-download"]` desktop /
 * `-mobile` on narrow viewports) AND the modern player drawer
 * (`[data-testid="drawer-demo-download"]`) once a ban has an attached
 * demo — both hrefs point at `getdemo.php?type=B&id=<bid>`, and
 * actually clicking the drawer's link must produce a real browser
 * download carrying the demo's `origname`.
 */

import { createHash } from 'node:crypto';

import { expect, test } from '../../fixtures/auth.ts';
import { expectNoCriticalA11y } from '../../fixtures/axe.ts';
import { removeBanDemoE2e, seedBanDemoE2e } from '../../fixtures/db.ts';
import { seedBanViaApi } from '../../fixtures/seeds.ts';

test.describe('flow: ban demo download (#1554)', () => {
    test('row and drawer expose the attached demo download', async ({ page, isMobile }, testInfo) => {
        const uniq = `${testInfo.workerIndex}${testInfo.retry}${Date.now()}`;
        // 32-hex basename, same shape as UploadHandler's renameToHash
        // output: if the finally-block cleanup never runs (the page died
        // before the panel JS loaded), `./sbpp.sh db-reset`'s MD5-name
        // sweep of web/demos/ still removes the orphan.
        const filename = createHash('md5').update(`e2e-demo-1554-${uniq}`).digest('hex');
        const originalName = 'evidence-1554.dem';

        const seeded = await seedBanViaApi(page, {
            nickname: `e2e-demo-1554-w${testInfo.workerIndex}-r${testInfo.retry}`,
            steam: `STEAM_0:1:${6_554_000 + testInfo.workerIndex * 10 + testInfo.retry}`,
            reason: 'e2e demo download',
        });

        await seedBanDemoE2e(seeded.bid, filename, originalName);

        try {
            await page.goto('/index.php?p=banlist');

            const rowTestId = isMobile ? 'ban-card' : 'ban-row';
            const downloadTestId = isMobile
                ? 'row-action-demo-download-mobile'
                : 'row-action-demo-download';
            const row = page.locator(`[data-testid="${rowTestId}"][data-id="${seeded.bid}"]`);
            const rowDownload = row.locator(`[data-testid="${downloadTestId}"]`);
            await expect(rowDownload).toBeVisible();
            await expect(rowDownload).toHaveAttribute(
                'href',
                `getdemo.php?type=B&id=${seeded.bid}`,
            );

            await row.locator('[data-testid="drawer-trigger"]').click();

            const drawer = page.locator('#drawer-root');
            await expect(drawer).toHaveAttribute('data-drawer-open', 'true');
            await expect(drawer).not.toHaveAttribute('data-loading', /.+/);

            const drawerDownload = drawer.locator('[data-testid="drawer-demo-download"]');
            await expect(drawerDownload).toBeVisible();
            await expect(drawerDownload).toHaveAttribute(
                'href',
                `getdemo.php?type=B&id=${seeded.bid}`,
            );
            await expectNoCriticalA11y(page, testInfo, { include: ['#drawer-root'] });

            const downloadPromise = page.waitForEvent('download');
            await drawerDownload.click();
            const download = await downloadPromise;
            expect(download.suggestedFilename()).toBe(originalName);
        } finally {
            // Through the shim, not bans.remove_demo: www-data usually
            // can't unlink the CLI-written file from a bind-mounted
            // web/demos/, so the JSON action would fail (silently here).
            await removeBanDemoE2e(seeded.bid);
        }
    });
});
