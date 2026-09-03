/**
 * Flow spec — upstream issue sbpp/sourcebans-pp#1436: the web admin
 * groups permission flag grid needs a bulk toggle so operators don't
 * have to tick every permission checkbox individually.
 *
 * What this locks in
 * ------------------
 * `?p=admin&c=groups&section=list` renders the master-detail flag grid
 * (one checkbox per web-permission flag). Two buttons next to the
 * "Permission flags" label:
 *   - `[data-testid="flag-select-all"]`  — checks every enabled flag
 *   - `[data-testid="flag-select-none"]` — unchecks every flag
 * Both refresh the live `[data-testid="flag-bitmask"]` preview, and the
 * folded OR-sum round-trips through Save exactly like a manual toggle.
 *
 * Project gating mirrors `admin-groups-bitmask.spec.ts` (desktop
 * chromium only; the spec mutates the shared e2e DB).
 */

import { expect, test } from '../../fixtures/auth.ts';
import { truncateE2eDb } from '../../fixtures/db.ts';

const GROUPS_LIST_ROUTE = '/index.php?p=admin&c=groups&section=list';

const FIXTURE = {
    groupName: 'e2e-select-all-flags-group',
};

test.describe('flow: admin groups select-all permission flags (upstream #1436)', () => {
    test.skip(({ isMobile }) => isMobile, 'flow spec runs only on desktop chromium');

    test.beforeEach(async () => {
        await truncateE2eDb();
    });

    test('Select all / Select none toggle the whole flag grid', async ({ page }) => {
        await page.goto('/');

        const seedEnvelope = await page.evaluate(async (groupName) => {
            const w = window as unknown as {
                sb: {
                    api: {
                        call: (
                            action: string,
                            params: Record<string, unknown>,
                        ) => Promise<{ ok: boolean; error?: { code: string; message: string } }>;
                    };
                };
                Actions: Record<string, string>;
            };
            return await w.sb.api.call(w.Actions.GroupsAdd, {
                name: groupName,
                type: '1',
                bitmask: 0,
                srvflags: '',
            });
        }, FIXTURE.groupName);

        expect(seedEnvelope.ok, `groups.add must succeed: ${JSON.stringify(seedEnvelope)}`).toBe(true);

        await page.goto(GROUPS_LIST_ROUTE);

        const detail = page.locator('[data-testid="group-detail"]');
        await expect(detail).toBeVisible();

        const flagGrid = detail.locator('[data-testid="flag-grid"]');
        const bitmaskBadge = detail.locator('[data-testid="flag-bitmask"]');
        const selectAll = detail.locator('[data-testid="flag-select-all"]');
        const selectNone = detail.locator('[data-testid="flag-select-none"]');
        const checkboxes = flagGrid.locator('input[name="flags[]"]');

        await expect(flagGrid).toBeVisible();
        await expect(selectAll).toBeVisible();
        await expect(bitmaskBadge).toHaveText(/^0 bitmask$/);

        const total = await checkboxes.count();
        expect(total).toBeGreaterThan(0);

        // ---- Select all → every checkbox checked, badge non-zero ----------
        await selectAll.click();
        for (let i = 0; i < total; i++) {
            await expect(checkboxes.nth(i)).toBeChecked();
        }
        await expect(bitmaskBadge).not.toHaveText(/^0 bitmask$/);
        await expect(bitmaskBadge).not.toContainText('-');

        // ---- Save round-trips the folded OR-sum --------------------------
        const saveButton = detail.locator('[data-testid="group-save"]');
        const editResponsePromise = page.waitForResponse(
            (response) =>
                response.url().includes('api.php') &&
                response.request().method() === 'POST' &&
                response.status() === 200,
        );
        await saveButton.click();
        const editEnvelope = await (await editResponsePromise).json();
        expect(editEnvelope.ok, `groups.edit must succeed: ${JSON.stringify(editEnvelope)}`).toBe(true);

        await page.goto(GROUPS_LIST_ROUTE);
        const reloadedGrid = page.locator('[data-testid="flag-grid"]');
        await expect(reloadedGrid.locator('input[name="flags[]"]').first()).toBeChecked();

        // ---- Select none → every checkbox cleared, badge back to 0 -------
        await page.locator('[data-testid="flag-select-none"]').click();
        const reloadedChecks = reloadedGrid.locator('input[name="flags[]"]');
        const reloadedTotal = await reloadedChecks.count();
        for (let i = 0; i < reloadedTotal; i++) {
            await expect(reloadedChecks.nth(i)).not.toBeChecked();
        }
        await expect(page.locator('[data-testid="flag-bitmask"]')).toHaveText(/^0 bitmask$/);
    });
});
