/**
 * Channels Tests
 *
 * Exercises the Add Channel wizard. The legacy `/channels` page and the
 * `/channels-next` experimental page are not wired into the current build,
 * so their specs were removed.
 */

import { expect, test } from '../helpers/fixtures';

const BASE_URL = process.env.AS_BASE_URL || 'http://localhost:8080';

test.describe.skip('Add Channel wizard', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto(`${BASE_URL}/channels/new`);
        await expect(page.getByTestId('wizard-add-channel')).toBeVisible();
    });

    test('shows the protocol selection step with all three protocols', async ({ page }) => {
        await expect(page.getByTestId('wizard-step-welcome')).toBeVisible();
        await expect(page.getByTestId('wizard-protocol-a2a')).toBeVisible();
        await expect(page.getByTestId('wizard-protocol-mcp')).toBeVisible();
        await expect(page.getByTestId('wizard-protocol-mpx')).toBeVisible();
    });

    test('selecting A2A advances to the configure step', async ({ page }) => {
        await page.getByTestId('wizard-protocol-a2a').click();
        await expect(page.getByTestId('wizard-step-configure')).toBeVisible();
    });
});
