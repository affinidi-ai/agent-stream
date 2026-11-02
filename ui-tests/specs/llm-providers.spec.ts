/**
 * LLM Providers Page Tests
 *
 * The LlmProvidersPage (www/default/src/pages/LlmProvidersPage.tsx) is routed at
 * /llm-providers and carries the page-llm-providers / llm-providers-add-button /
 * llm-providers-row-* test IDs. The provider catalog is served by
 * GET /api/v1/llm-providers.
 */

import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AS_BASE_URL || 'http://localhost:8080';
const LLM_PROVIDERS_URL = `${BASE_URL}/llm-providers`;

test.describe('LLM Providers page', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(LLM_PROVIDERS_URL);
        await expect(page.getByTestId('page-llm-providers')).toBeVisible();
    });

    test('renders the page root', async ({page}) => {
        await expect(page.getByTestId('page-llm-providers')).toBeVisible();
    });

    test('exposes the sidebar nav entry', async ({page}) => {
        await expect(page.getByTestId('nav-llm-providers')).toBeVisible();
    });
});

test.describe('LLM Providers navigation', () => {
    test('navigates from the sidebar to the providers list', async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard`);
        await expect(page.getByTestId('page-dashboard')).toBeVisible();
        await page.getByTestId('nav-llm-providers').click();
        await expect(page.getByTestId('page-llm-providers')).toBeVisible();
    });
});
