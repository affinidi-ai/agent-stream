# UI Automated Tests

Automated UI tests for the Agent Stream dashboard using Playwright.

## Prerequisites

- Node.js 18+
- npm or yarn
- A debug build of Agent Stream in test mode (`make ui-test` starts one for you)

## Quick Start

```bash
# From repository root: prepare envs/local-tests, build, start Agent Stream in
# test mode, run the suite, stop Agent Stream
make ui-test

# View the HTML report
make ui-test-report
```

## Setup

```bash
# Install dependencies
npm install

# Install Playwright browsers
npx playwright install chromium
```

## Running Tests

### Against a running instance

`make ui-test` runs [`scripts/l-run-ui-tests.sh`](../scripts/l-run-ui-tests.sh), which
boots its own instance. To run the suite from this directory against an instance you
started yourself:

1. **Start Agent Stream in test mode** from the repository root. `tk=1` sets
   `AS_TEST_MODE=true` and `AS_TEST_TOKEN=testkit-secret-token`:
   ```bash
   make run-debug tk=1
   ```

2. **Point the tests at it**:
   ```bash
   export AS_BASE_URL=http://localhost:8080      # Agent Stream HTTP listener
   export AS_TEST_TOKEN=testkit-secret-token     # Must match the running instance
   ```

### Environment variables

| Variable | Default | Used by |
| --- | --- | --- |
| `AS_BASE_URL` | `http://localhost:8080` (the runner uses the env's HTTP port) | Playwright config, specs |
| `AS_TEST_TOKEN` | `test-token-12345` | Runner and test-auth helper |
| `AS_TEST_MODE` | set to `true` by the runner | Agent Stream test-auth endpoint |
| `AS_ENV_DIR` | `envs/local-tests` | Runner, global setup |
| `AS_HTTP_PORT` | port from `envs/local-tests/instance.env` | Runner |
| `AS_SKIP_BUILD` | unset | Runner: `true` skips the cargo and UI builds |
| `AS_SKIP_UI_BUILD` | unset | Global setup: `true` skips the UI bundle freshness check |
| `AS_RESULT_DIR` | `./test_results/result_<timestamp>` | Playwright config: result directory for the run |

### Run All Tests

```bash
npm run test:ui
# Or from repo root:
make ui-test
```

### Run in Headed Mode (Visible Browser)

```bash
npm run test:ui:headed
# Or from repo root:
make ui-test-headed
```

### Debug Mode (Step Through Tests)

```bash
npm run test:ui:debug
```

### View HTML Report

```bash
npm run test:ui:report
# Or from repo root:
make ui-test-report
```

### Generate Test Code

```bash
npm run test:ui:codegen
```

## Test Results

Test results are stored in **timestamped directories** for comparison and historical analysis:

```
test_results/
├── result_20260128_143052/   # Timestamped result directory
│   ├── html/                 # Interactive HTML report
│   ├── screenshots/          # Test screenshots
│   ├── traces/               # Playwright traces (on failure)
│   ├── test-output/          # Raw test output
│   ├── results.json          # Machine-readable JSON results
│   ├── junit.xml             # JUnit XML for CI integration
│   └── test-metadata.json    # Run metadata and summary
├── result_20260128_120000/   # Previous run (preserved for comparison)
├── latest/                   # Symlink to most recent run
└── .auth/                    # Shared authentication state
```

### Comparing Test Results

To compare results across runs:

```bash
# Compare pass/fail rates
diff test_results/result_20260128_120000/results.json \
     test_results/result_20260128_143052/results.json

# Compare screenshots visually
open test_results/result_*/screenshots/
```

## Test Structure

```
ui-tests/
├── specs/                    # Test specifications
│   ├── dashboard.spec.ts     # Dashboard page tests
│   ├── navigation.spec.ts    # Navigation tests
│   ├── llm-providers.spec.ts # LLM Providers page tests
│   ├── terms-consent.spec.ts # Terms consent tests
│   ├── channels.spec.ts      # Add Channel wizard (skipped)
│   ├── api-keys.spec.ts      # API Keys page tests (skipped)
│   ├── credentials.spec.ts   # Outbound Credentials tests
│   └── accessibility.spec.ts # WCAG accessibility tests
├── helpers/                  # Test utilities
│   ├── fixtures.ts           # `test`/`expect` with the authenticated context fixture
│   ├── test-auth.ts          # Authentication helpers
│   ├── screenshots.ts        # Screenshot utilities
│   ├── wait.ts               # Custom wait functions
│   └── index.ts              # Helper exports
├── test_results/             # Test output (gitignored), one result_<timestamp>/ per run
│   ├── latest -> result_<timestamp>/
│   └── result_<timestamp>/
│       ├── screenshots/      # Test screenshots
│       ├── traces/           # Playwright traces
│       ├── html/             # HTML report
│       ├── results.json      # JSON results
│       └── junit.xml         # JUnit XML report
├── auth.setup.ts             # Authentication setup
├── global-setup.ts           # Test suite setup
├── global-teardown.ts        # Test suite teardown
├── playwright.config.ts      # Playwright configuration
├── package.json              # Dependencies
└── tsconfig.json             # TypeScript config
```

## Test Authentication

Tests use a bypass mechanism to avoid WebAuthn passkey authentication:

1. Agent Stream must be started with `AS_TEST_MODE=true` **and** a non-empty `AS_TEST_TOKEN`. The endpoint fails closed: if `AS_TEST_TOKEN` is unset or blank it stays disabled (there is no default token). The endpoint is also compiled into **debug builds only** — a `--release` binary never contains it.
2. Tests call `/api/internal/test-support/auth/login` with `X-Test-Token` header
3. Agent Stream provisions or reuses an approved synthetic test user, then creates a real session for that user
4. Agent Stream sets the session cookie through the shared auth finalizer, while the Playwright helper keeps `sessionStorage` aligned with the current frontend contract

### Security Note

⚠️ **Never enable test mode in production!**

Test mode should only be used for:

- Local development
- CI/CD pipelines
- Automated testing environments

## Test Results

Each run writes into `test_results/result_<timestamp>/`, and `test_results/latest` points at the most recent run:

| File/Directory       | Description                        |
|----------------------|------------------------------------|
| `screenshots/`       | Full-page and element screenshots  |
| `traces/`            | Playwright traces for failed tests |
| `html/`              | Interactive HTML report            |
| `results.json`       | JSON test results                  |
| `junit.xml`          | JUnit XML for CI integration       |
| `test-metadata.json` | Run metadata and summary           |

### Viewing the HTML Report

```bash
npx playwright show-report test_results/latest/html
```

## Writing New Tests

### Selector convention

**Specs MUST select elements via `page.getByTestId(...)`.** Text, CSS-class, and
`:has-text()` selectors are not allowed in new specs — they are brittle and silently
pass when the UI changes shape.

The dashboard exposes stable `data-testid` attributes per the convention documented in
[`www/default/AGENTS.md`](../www/default/AGENTS.md#frontend-working-rules).
Reserved patterns:

| Purpose | Pattern | Example |
|---|---|---|
| Page root | `page-<area>` | `page-governance` |
| Primary CTA | `<area>-<verb>-button` | `apikey-create-button` |
| List item / row | `<area>-card-<id>` / `<area>-row-<id>` | `apikey-row-<id>` |
| Empty state | `<area>-empty-state` | `terms-empty-state` |
| Form field | `<form>-<field>` | `<form>-name` |
| Modal root | `<area>-modal` | `apikey-create-modal` |
| Sidebar nav item | `nav-<route-key>` | `nav-governance` |
| Wizard root + steps | `wizard-<name>`, `wizard-step-<name>` | `wizard-<name>`, `wizard-step-configure` |
| Wizard navigation | `wizard-next`, `wizard-back`, `wizard-submit` | (shared across all wizards) |

If you need a testid that does not yet exist on the dashboard, add it to the React
component first (see the `data-testid` rules in [`www/default/AGENTS.md`](../www/default/AGENTS.md)),
then write the spec against it. Do not work around
a missing testid with text/class selectors.

### Assertion rules

- Use hard `expect(...)` assertions. Soft patterns like `expect(count).toBeGreaterThanOrEqual(0)`
  or `if (await el.count() > 0) { ... }` are not real assertions — a green run must mean
  the feature works.
- Wait on testid visibility, not arbitrary timeouts. `await expect(page.getByTestId('page-governance')).toBeVisible()`
  is preferred over `waitForTimeout`.

### Basic test structure

```typescript
import { expect, test } from '../helpers/fixtures';

const BASE_URL = process.env.AS_BASE_URL || 'http://localhost:8080';

test.describe('Governance Records', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/governance`);
    await expect(page.getByTestId('page-governance')).toBeVisible();
  });

  test('exposes the sidebar nav entry', async ({ page }) => {
    await expect(page.getByTestId('nav-governance')).toBeVisible();
  });
});
```

### Using Helpers

```typescript
import { test, expect } from '@playwright/test';
import {
  loginAsTestUser,
  captureFullPage,
  waitForNetworkIdle
} from './helpers';

test('authenticated test', async ({ page }) => {
  await loginAsTestUser(page);
  await waitForNetworkIdle(page);
  await captureFullPage(page, 'after-login');
});
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run UI Tests
  run: |
    cd ui-tests
    npm ci
    npx playwright install chromium
    npm run test:ui
  env:
    AS_TEST_MODE: 'true'
    AS_TEST_TOKEN: ${{ secrets.AS_TEST_TOKEN }}

- name: Upload Test Results
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: ui-test-results
    path: ui-tests/test_results/
```

## Troubleshooting

### Tests fail because Agent Stream is not reachable

Use `make ui-test`, which starts Agent Stream itself (its log is `/tmp/agent-stream-ui-tests.log`),
or start an instance before running the suite:

```bash
make run-debug tk=1
```

### Tests fail with "Test mode not enabled"

Start Agent Stream with test mode (`make run-debug tk=1`, or set `AS_TEST_MODE=true` and a
non-empty `AS_TEST_TOKEN` yourself).

### Tests fail with "Unauthorized"

Check that `AS_TEST_TOKEN` matches between Agent Stream and the test environment.

### Screenshots are blank

Ensure the page has fully loaded before taking screenshots:

```typescript
await page.waitForLoadState('networkidle');
```

### Tests timeout

Increase timeout in `playwright.config.ts` or individual tests:

```typescript
test.setTimeout(60000); // 60 seconds
```

## License

Same as parent project.
