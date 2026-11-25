/**
 * #108: passkeys end to end with Chromium's virtual authenticator (CDP
 * WebAuthn domain), on a dedicated admin (seed2faAdminE2e): add one from
 * Your account, sign in with it alone, then use it as the second step
 * after the password.
 */
import { expect, test, type Page } from '@playwright/test';
import { seed2faAdminE2e } from '../../fixtures/db.ts';

async function passwordSignIn(page: Page, user: string, password: string): Promise<void> {
    await page.goto('/index.php?p=login');
    await page.getByTestId('login-username').fill(user);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('login-submit').click();
}

test.describe('passkeys', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

    test('add a passkey, sign in with it, use it as the second step', async ({ page, context }, testInfo) => {
        const name = `e2e-2fa-pk-${testInfo.project.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`.slice(0, 48);
        const admin = await seed2faAdminE2e(name);

        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable');
        await cdp.send('WebAuthn.addVirtualAuthenticator', {
            options: {
                protocol: 'ctap2',
                transport: 'internal',
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
                automaticPresenceSimulation: true,
            },
        });

        await passwordSignIn(page, admin.user, admin.password);
        await page.waitForURL((url) => !url.search.includes('p=login'));

        await page.goto('/index.php?p=account');
        await expect(page.getByTestId('account-passkeys-empty')).toBeVisible();
        await page.getByTestId('account-passkey-name').fill('Virtual key');
        await page.getByTestId('account-passkey-password').fill(admin.password);
        await page.getByTestId('account-passkey-add').click();
        // First second factor: the recovery codes are shown once.
        await expect(page.locator('#account-passkey-codes')).toHaveText(/^([A-Z2-7]{4}-){3}[A-Z2-7]{4}/);
        await page.reload();
        await expect(page.getByTestId('account-passkey-row')).toHaveCount(1);
        await expect(page.getByTestId('account-passkey-row')).toContainText('Virtual key');

        // Passwordless: the passkey alone signs in.
        await context.clearCookies();
        await page.goto('/index.php?p=login');
        await page.getByTestId('login-passkey').click();
        await page.waitForURL((url) => !url.search.includes('p=login'));
        await page.goto('/index.php?p=account');
        await expect(page.getByTestId('account-passkeys')).toBeVisible();

        // Password sign-in now needs the second step; the passkey answers it.
        await context.clearCookies();
        await passwordSignIn(page, admin.user, admin.password);
        await page.waitForURL(/p=login&step=2fa/);
        await page.getByTestId('login-2fa-passkey').click();
        await page.waitForURL((url) => !url.search.includes('p=login'));
        await page.goto('/index.php?p=account');
        await expect(page.getByTestId('account-passkeys')).toBeVisible();
    });
});
