const { test, expect } = require('@playwright/test');

test('browser launches and works locally', async ({ page }) => {
  // Navigate to a data URL (no external network needed)
  await page.goto('data:text/html,<html><body><h1>Hello Playwright!</h1><button id="myBtn">Click me</button></body></html>');

  // Verify the heading is visible
  const heading = page.locator('h1');
  await expect(heading).toBeVisible();
  await expect(heading).toHaveText('Hello Playwright!');

  // Interact with the button
  const button = page.locator('#myBtn');
  await expect(button).toBeVisible();
  await button.click();
});

test('page can execute JavaScript', async ({ page }) => {
  await page.goto('data:text/html,<html><body><div id="output"></div></body></html>');

  // Execute JavaScript
  const result = await page.evaluate(() => {
    const div = document.getElementById('output');
    div.textContent = 'JavaScript works!';
    return div.textContent;
  });

  expect(result).toBe('JavaScript works!');
});

test('can fill forms and interact with elements', async ({ page }) => {
  await page.goto('data:text/html,<html><body><input id="name" /><button id="submit">Submit</button></body></html>');

  // Fill the input
  await page.fill('#name', 'Test User');

  // Verify the value
  const value = await page.inputValue('#name');
  expect(value).toBe('Test User');

  // Click the button
  await page.click('#submit');
});
