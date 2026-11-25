/**
 * #107: two-factor authentication end to end, on a dedicated admin
 * (seed2faAdminE2e): turn it on from Your account, then sign in again
 * with the password and the code.
 */
import { createHmac } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { seed2faAdminE2e } from '../../fixtures/db.ts';

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), `offset` steps from now. */
function totp(base32: string, offset = 0): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of base32.replace(/[\s=]/g, '').toUpperCase()) {
        bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
    }
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    const step = Math.floor(Date.now() / 1000 / 30) + offset;
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const h = createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
    const o = h[19] & 0x0f;
    const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
    return String(bin % 1_000_000).padStart(6, '0');
}

async function passwordSignIn(page: Page, user: string, password: string): Promise<void> {
    await page.goto('/index.php?p=login');
    await page.getByTestId('login-username').fill(user);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('login-submit').click();
}

test.describe('two-factor authentication', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

    test('turn it on, then sign in with password + code', async ({ page, context }, testInfo) => {
        const name = `e2e-2fa-${testInfo.project.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`.slice(0, 48);
        const admin = await seed2faAdminE2e(name);

        // No 2FA yet: the password alone signs in.
        await passwordSignIn(page, admin.user, admin.password);
        await page.waitForURL((url) => !url.search.includes('p=login'));

        await page.goto('/index.php?p=account');
        const card = page.getByTestId('account-2fa');
        await expect(card).toHaveAttribute('data-enabled', '0');
        await page.getByTestId('account-2fa-password').fill(admin.password);
        await page.getByTestId('account-2fa-setup').click();
        await expect(page.getByTestId('account-2fa-qr')).toHaveAttribute('src', /^data:image\/svg\+xml;base64,/);
        const secret = (await page.getByTestId('account-2fa-secret').textContent()) ?? '';
        expect(secret.replace(/\s/g, '')).toMatch(/^[A-Z2-7]{32}$/);

        await page.getByTestId('account-2fa-code').fill('000000');
        await page.getByTestId('account-2fa-confirm').click();
        await expect(page.getByTestId('account-2fa-msg')).toContainText("isn't valid");

        await page.getByTestId('account-2fa-code').fill(totp(secret));
        await page.getByTestId('account-2fa-confirm').click();
        const codes = page.getByTestId('account-2fa-codes');
        await expect(codes).toBeVisible();
        await expect(codes.locator('pre')).toHaveText(/^([A-Z2-7]{4}-){3}[A-Z2-7]{4}(\n([A-Z2-7]{4}-){3}[A-Z2-7]{4}){9}$/);

        // Sign in again: the password now leads to the code step, with no session.
        await context.clearCookies();
        await passwordSignIn(page, admin.user, admin.password);
        await page.waitForURL(/p=login&step=2fa/);
        await page.goto('/index.php?p=account');
        await expect(page.getByTestId('account-2fa')).toHaveCount(0);

        await page.goto('/index.php?p=login&step=2fa');
        await page.getByTestId('login-2fa-code').fill('000000');
        await page.getByTestId('login-2fa-submit').click();
        await expect(page.getByTestId('login-2fa-error')).toContainText("isn't valid");

        // The setup used the current step; the next one is still accepted.
        await page.getByTestId('login-2fa-code').fill(totp(secret, 1));
        await page.getByTestId('login-2fa-submit').click();
        await page.waitForURL((url) => !url.search.includes('p=login'));
        await page.goto('/index.php?p=account');
        await expect(page.getByTestId('account-2fa')).toHaveAttribute('data-enabled', '1');
    });

    test('the code step without a pending sign-in sends back to the login page', async ({ page }) => {
        await page.goto('/index.php?p=login&step=2fa');
        await page.waitForURL(/m=2fa_expired/);
        await expect(page.getByTestId('login-form')).toBeVisible();
    });
});
