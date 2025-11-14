# Playwright Setup

## Installation Status

✅ Playwright package (@playwright/test) has been installed as a dev dependency.

## Browser Installation

To complete the Playwright setup, you'll need to install the browsers in your local environment:

```bash
npx playwright install
```

Or install specific browsers:

```bash
npx playwright install chromium
npx playwright install firefox
npx playwright install webkit
```

To install browsers with system dependencies (Linux):

```bash
npx playwright install --with-deps
```

## Getting Started

Create a simple test file to verify the setup:

```javascript
// tests/example.spec.js
const { test, expect } = require('@playwright/test');

test('basic test', async ({ page }) => {
  await page.goto('https://playwright.dev/');
  const title = await page.title();
  expect(title).toBe('Fast and reliable end-to-end testing for modern web apps | Playwright');
});
```

Run tests:

```bash
npx playwright test
```

## Documentation

- [Playwright Documentation](https://playwright.dev/)
- [API Reference](https://playwright.dev/docs/api/class-playwright)
