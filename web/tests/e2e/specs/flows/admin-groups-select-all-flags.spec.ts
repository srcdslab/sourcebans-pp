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
 * The expected bitmask is recomputed in-spec from each checkbox's
 * `data-flag-value` with plain (non-bitwise) arithmetic — deliberately
 * NOT reusing the page's `SbppFoldFlags`, so the assertion stays an
 * independent oracle rather than a tautology. `$all_flags` strips the
 * `ALL_WEB` / `ADMIN_OWNER` meta entries (see `web/pages/admin.groups.php`),
 * but the remainder still includes `ADMIN_UNBAN_GROUP_BANS` (bit 31), so
 * "select all" is exactly the case where a bare `|=` OR-fold would go
 * negative — the #1272 regression this spec re-guards on the bulk path.
 *
 * A bulk toggle also has to arm the master-detail dirty tracker: setting
 * `.checked` from script fires no `change`, so without an explicit
 * dispatch the left-rail selection handler would consider the pane
 * pristine and drop the operator's bulk change with no prompt. The
 * second test locks that in via the shared confirm `<dialog>`
 * (`[data-testid="sbpp-confirm-dialog"]`).
 *
 * Project gating mirrors `admin-groups-bitmask.spec.ts` (desktop
 * chromium only; the spec mutates the shared e2e DB).
 */

import type { Page } from '@playwright/test';

import { expect, test } from '../../fixtures/auth.ts';
import { truncateE2eDb } from '../../fixtures/db.ts';

const GROUPS_LIST_ROUTE = '/index.php?p=admin&c=groups&section=list';

const FIXTURE = {
    groupA: 'e2e-select-all-flags-group-a',
    groupB: 'e2e-select-all-flags-group-b',
};

async function seedWebGroup(page: Page, name: string): Promise<void> {
    const envelope = await page.evaluate(async (groupName) => {
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
    }, name);

    expect(envelope.ok, `groups.add must succeed: ${JSON.stringify(envelope)}`).toBe(true);
}

/**
 * Independent OR-fold of every rendered flag value, computed with
 * addition over a de-duplicated bit set instead of `|=` so the oracle
 * cannot reproduce the signed-Int32 bug it is meant to catch.
 */
async function expectedSelectAllBitmask(page: Page): Promise<number> {
    return await page.evaluate(() => {
        const inputs = Array.from(
            document.querySelectorAll<HTMLInputElement>(
                '[data-testid="flag-grid"] input[name="flags[]"]',
            ),
        );
        const bits = new Set<number>();
        for (const input of inputs) {
            if (input.disabled) continue;
            const value = Number(input.dataset.flagValue || input.value);
            for (let bit = 0; bit < 32; bit++) {
                // `Math.floor(value / 2 ** bit) % 2` — no bitwise ops.
                if (Math.floor(value / 2 ** bit) % 2 === 1) bits.add(bit);
            }
        }
        let total = 0;
        bits.forEach((bit) => {
            total += 2 ** bit;
        });
        return total;
    });
}

test.describe('flow: admin groups select-all permission flags (upstream #1436)', () => {
    test.skip(({ isMobile }) => isMobile, 'flow spec runs only on desktop chromium');

    test.beforeEach(async () => {
        await truncateE2eDb();
    });

    test('Select all / Select none toggle the whole flag grid and round-trip', async ({ page }) => {
        await page.goto('/');
        await seedWebGroup(page, FIXTURE.groupA);

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
        await expect(selectNone).toBeVisible();
        // Real buttons, not links styled as buttons — a submitting
        // control here would POST the JS-less form and lose the change.
        await expect(selectAll).toHaveAttribute('type', 'button');
        await expect(selectNone).toHaveAttribute('type', 'button');
        await expect(bitmaskBadge).toHaveText(/^0 bitmask$/);

        const total = await checkboxes.count();
        expect(total).toBeGreaterThan(0);

        const expected = await expectedSelectAllBitmask(page);
        // Sanity: the grid must still carry a bit-31 flag, otherwise this
        // spec silently stops guarding the unsigned-fold path.
        expect(expected, 'select-all must exercise bit 31 (see #1272)').toBeGreaterThanOrEqual(
            2 ** 31,
        );

        // ---- Select all → every checkbox checked, badge = unsigned OR ----
        await selectAll.click();
        for (let i = 0; i < total; i++) {
            await expect(checkboxes.nth(i)).toBeChecked();
        }
        await expect(bitmaskBadge).toHaveText(`${expected} bitmask`);
        await expect(bitmaskBadge).not.toContainText('-');

        // Idempotent: a second press changes nothing and must not corrupt
        // the preview.
        await selectAll.click();
        await expect(bitmaskBadge).toHaveText(`${expected} bitmask`);

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
        expect(editEnvelope.ok, `groups.edit must succeed: ${JSON.stringify(editEnvelope)}`).toBe(
            true,
        );

        // SSR re-render must show the same unsigned value and every flag
        // re-checked — not just the first one.
        await page.goto(GROUPS_LIST_ROUTE);
        const reloadedDetail = page.locator('[data-testid="group-detail"]');
        const reloadedGrid = reloadedDetail.locator('[data-testid="flag-grid"]');
        const reloadedBadge = reloadedDetail.locator('[data-testid="flag-bitmask"]');
        await expect(reloadedBadge).toHaveText(`${expected} bitmask`);
        await expect(reloadedBadge).not.toContainText('-');

        const reloadedChecks = reloadedGrid.locator('input[name="flags[]"]');
        const reloadedTotal = await reloadedChecks.count();
        expect(reloadedTotal).toBe(total);
        for (let i = 0; i < reloadedTotal; i++) {
            await expect(reloadedChecks.nth(i)).toBeChecked();
        }

        // ---- Select none → every checkbox cleared, badge back to 0 -------
        await reloadedDetail.locator('[data-testid="flag-select-none"]').click();
        for (let i = 0; i < reloadedTotal; i++) {
            await expect(reloadedChecks.nth(i)).not.toBeChecked();
        }
        await expect(reloadedBadge).toHaveText(/^0 bitmask$/);
    });

    test('a bulk toggle arms the unsaved-changes guard', async ({ page }) => {
        await page.goto('/');
        await seedWebGroup(page, FIXTURE.groupA);
        await seedWebGroup(page, FIXTURE.groupB);

        await page.goto(GROUPS_LIST_ROUTE);

        const detail = page.locator('[data-testid="group-detail"]');
        await expect(detail).toBeVisible();

        const rows = page.locator('[data-testid="group-row"]');
        const otherRow = rows.filter({ hasText: FIXTURE.groupB });
        const currentName = await detail
            .locator('[data-testid="group-detail-name"]')
            .textContent();
        // The master-detail pane auto-selects the first row; pick whichever
        // of the two seeded groups is NOT currently painted.
        const target =
            currentName?.trim() === FIXTURE.groupB ? rows.filter({ hasText: FIXTURE.groupA }) : otherRow;
        await expect(target).toHaveCount(1);

        await detail.locator('[data-testid="flag-select-all"]').click();

        // Programmatic `.checked =` fires no `change`; without an explicit
        // dispatch the selection handler would repaint straight over the
        // bulk change with no prompt.
        await target.click();
        const confirmDialog = page.locator('[data-testid="sbpp-confirm-dialog"]');
        await expect(confirmDialog).toBeVisible();
        await expect(page.locator('[data-testid="sbpp-confirm-title"]')).toHaveText(
            'Unsaved changes',
        );

        // Cancelling keeps the operator on the edited group with the bulk
        // selection intact.
        await page.locator('[data-testid="sbpp-confirm-cancel"]').click();
        await expect(confirmDialog).toBeHidden();
        await expect(
            detail.locator('[data-testid="flag-grid"] input[name="flags[]"]').first(),
        ).toBeChecked();
    });
});
