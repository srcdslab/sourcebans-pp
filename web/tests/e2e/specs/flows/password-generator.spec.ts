/**
 * Flow spec — configurable password generator.
 *
 * Every "Generate password" button (`[data-password-generator]`)
 * opens the shared dialog from `web/scripts/password-generator.js`,
 * which calls `Actions.AdminsGeneratePassword` and fills the inputs
 * named in `data-password-targets` on "Use password".
 *
 * What this locks in:
 *   1. Per-password options (length, character sets) reach the server
 *      and shape the output; an empty character-set selection blocks
 *      "Use password" with an inline error.
 *   2. The owner-configured defaults (`config.password.generator.*`)
 *      seed the dialog.
 *   3. The generator is wired on Edit admin and Your account.
 *   4. The open dialog has no critical axe violations.
 *
 * Nothing here submits a form: the seeded `admin/admin` password
 * backs the suite's storage state and must stay unchanged.
 *
 * Selectors per AGENTS.md "Testability hooks":
 *   - `[data-testid="password-generator-dialog"]`  — the dialog
 *   - `[data-testid="password-generator-output"]`  — generated value
 *   - `[data-testid="password-generator-length"]`  — length input
 *   - `[data-testid="password-generator-<set>"]`   — set checkboxes
 *   - `[data-testid="password-generator-error"]`   — inline error
 *   - `[data-testid="password-generator-use"]`     — fill + close
 */

import type { Page } from '@playwright/test';
import { expect, test } from '../../fixtures/auth.ts';
import { expectNoCriticalA11y } from '../../fixtures/axe.ts';
import { setSettingE2e } from '../../fixtures/db.ts';

const ADD_ADMIN_ROUTE = '/index.php?p=admin&c=admins&section=add-admin';

const dialog = (page: Page) => page.locator('[data-testid="password-generator-dialog"]');
const output = (page: Page) => page.locator('[data-testid="password-generator-output"]');

/** Waits for the next `admins.generate_password` round-trip to settle. */
function nextGenerate(page: Page) {
    return page.waitForResponse(
        (r) =>
            r.url().includes('api.php') &&
            r.request().method() === 'POST' &&
            (r.request().postData() ?? '').includes('admins.generate_password'),
    );
}

async function openFrom(page: Page, triggerTestId: string): Promise<string> {
    const response = nextGenerate(page);
    await page.locator(`[data-testid="${triggerTestId}"]`).click();
    const env = await (await response).json();
    expect(env.ok, JSON.stringify(env)).toBe(true);
    await expect(dialog(page)).toBeVisible();
    await expect(output(page)).toHaveValue(env.data.password);
    return env.data.password as string;
}

test.describe('flow: configurable password generator', () => {
    test.skip(({ isMobile }) => isMobile, 'flow spec runs only on desktop chromium');

    test('options shape the password; no character set blocks "Use password"', async ({ page }, testInfo) => {
        await page.goto(ADD_ADMIN_ROUTE);
        await openFrom(page, 'admin-add-generate-password');

        await expectNoCriticalA11y(page, testInfo);

        // Digits only.
        for (const set of ['lowercase', 'uppercase', 'symbols']) {
            const box = page.locator(`[data-testid="password-generator-${set}"]`);
            if (await box.isChecked()) {
                const response = nextGenerate(page);
                await box.uncheck();
                await response;
            }
        }
        await expect(output(page)).toHaveValue(/^[0-9]+$/);

        // Exact length.
        const length = page.locator('[data-testid="password-generator-length"]');
        let response = nextGenerate(page);
        await length.fill('30');
        await length.press('Tab');
        await response;
        await expect(output(page)).toHaveValue(/^[0-9]{30}$/);

        // Nothing selected → inline error, "Use password" disabled.
        await page.locator('[data-testid="password-generator-digits"]').uncheck();
        await expect(page.locator('[data-testid="password-generator-error"]')).toBeVisible();
        await expect(page.locator('[data-testid="password-generator-use"]')).toBeDisabled();

        // Re-enabling a set recovers.
        response = nextGenerate(page);
        await page.locator('[data-testid="password-generator-uppercase"]').check();
        await response;
        await expect(page.locator('[data-testid="password-generator-error"]')).toBeHidden();
        await expect(output(page)).toHaveValue(/^[A-Z]{30}$/);
        await expect(page.locator('[data-testid="password-generator-use"]')).toBeEnabled();

        await page.locator('[data-testid="password-generator-use"]').click();
        await expect(dialog(page)).toBeHidden();
        await expect(page.locator('[data-testid="admin-add-password"]')).toHaveValue(/^[A-Z]{30}$/);
    });

    test.describe('configured defaults', () => {
        test.afterEach(async () => {
            await setSettingE2e('config.password.generator.length', '20');
            await setSettingE2e('config.password.generator.symbols', '1');
        });

        test('dialog opens with the owner-configured defaults', async ({ page }) => {
            await setSettingE2e('config.password.generator.length', '24');
            await setSettingE2e('config.password.generator.symbols', '0');

            await page.goto(ADD_ADMIN_ROUTE);
            const password = await openFrom(page, 'admin-add-generate-password');

            expect(password).toMatch(/^[A-Za-z0-9]{24}$/);
            await expect(page.locator('[data-testid="password-generator-length"]')).toHaveValue('24');
            await expect(page.locator('[data-testid="password-generator-symbols"]')).not.toBeChecked();
        });

        test('Settings > Main saves the generator defaults', async ({ page }) => {
            const route = '/index.php?p=admin&c=settings&section=settings';
            await page.goto(route);
            await page.locator('[data-testid="setting-pwgen-length"]').fill('26');
            await page.locator('[data-testid="setting-pwgen-symbols"]').uncheck();
            // The save POSTs natively, then the page bounces back after
            // a short toast; anchor on the POST response, not the toast.
            const saved = page.waitForResponse(
                (r) => r.request().method() === 'POST' && r.url().includes('c=settings'),
            );
            await page.locator('[data-testid="settings-save"]').click();
            expect((await saved).status()).toBe(200);

            await page.goto(route);
            await expect(page.locator('[data-testid="setting-pwgen-length"]')).toHaveValue('26');
            await expect(page.locator('[data-testid="setting-pwgen-symbols"]')).not.toBeChecked();
            await expect(page.locator('[data-testid="setting-pwgen-lowercase"]')).toBeChecked();
        });
    });

    test('Edit admin: fills new password + confirm', async ({ page }) => {
        await page.goto('/index.php?p=admin&c=admins');
        const aid = await page
            .locator('[data-testid="admin-row"][data-name="admin"]')
            .first()
            .getAttribute('data-id');
        expect(aid).toBeTruthy();

        await page.goto(`/index.php?p=admin&c=admins&o=editdetails&id=${aid}`);
        const password = await openFrom(page, 'edit-admin-generate-password');
        await page.locator('[data-testid="password-generator-use"]').click();

        await expect(page.locator('[data-testid="edit-admin-password"]')).toHaveValue(password);
        await expect(page.locator('[data-testid="edit-admin-password2"]')).toHaveValue(password);
    });

    test('Your account: fills new password + confirm', async ({ page }) => {
        await page.goto('/index.php?p=account');
        const password = await openFrom(page, 'account-generate-password');
        await page.locator('[data-testid="password-generator-use"]').click();

        await expect(page.locator('[data-testid="account-new-password"]')).toHaveValue(password);
        await expect(page.locator('[data-testid="account-confirm-password"]')).toHaveValue(password);
    });
});
