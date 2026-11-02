/**
 * API Keys Page Tests
 *
 * The ApiKeysPage component (www/default/src/pages/ApiKeysPage.tsx) carries
 * the page-api-keys / apikey-create-button / apikey-row-* / apikey-secret-modal
 * test IDs, but it is not currently mounted on any route in
 * www/default/src/pages/AuthenticatedApp.tsx — only the EditApiKeyPage is wired
 * to /apikeys/new and /apikeys/:id.
 *
 * These tests are skipped until the list page is routed. When that happens,
 * remove the `.skip` and update API_KEYS_URL.
 */

import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AS_BASE_URL || 'http://localhost:8080';
const API_KEYS_URL = `${BASE_URL}/apikeys`; // TODO: confirm once page is routed

test.describe.skip('API Keys page (unrouted — pending route wire-up)', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(API_KEYS_URL);
        await expect(page.getByTestId('page-api-keys')).toBeVisible();
    });

    test('renders the page root and create CTA', async ({page}) => {
        await expect(page.getByTestId('page-api-keys')).toBeVisible();
        await expect(page.getByTestId('apikey-create-button')).toBeVisible();
    });

    test('opens the create modal when the CTA is clicked', async ({page}) => {
        await page.getByTestId('apikey-create-button').click();
        await expect(page.getByTestId('apikey-create-modal')).toBeVisible();
    });
});
