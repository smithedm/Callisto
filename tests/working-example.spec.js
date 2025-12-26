const { test, expect } = require('@playwright/test');

test('Playwright is working - browser context test', async ({ context }) => {
  // Test that we can create a new page
  const page = await context.newPage();
  expect(page).toBeTruthy();
  await page.close();
});

test('Playwright is working - page evaluation test', async ({ page }) => {
  // Test JavaScript evaluation without navigation
  const result = await page.evaluate(() => {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      timestamp: Date.now()
    };
  });

  expect(result.userAgent).toBeTruthy();
  expect(result.platform).toBeTruthy();
  expect(result.timestamp).toBeGreaterThan(0);
});

test('Playwright is working - page methods test', async ({ page }) => {
  // Test basic page methods
  const title = await page.title();
  expect(title).toBeDefined();

  const url = page.url();
  expect(url).toBe('about:blank');
});
