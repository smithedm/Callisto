const { test, expect } = require('@playwright/test');

test('basic navigation test', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Check the page title
  await expect(page).toHaveTitle(/Playwright/);

  // Click on "Get started" link
  await page.getByRole('link', { name: 'Get started' }).click();

  // Verify we navigated to the docs
  await expect(page).toHaveURL(/.*docs.*/);
});

test('simple page interaction', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Get the main heading
  const heading = page.locator('h1').first();
  await expect(heading).toBeVisible();
});
