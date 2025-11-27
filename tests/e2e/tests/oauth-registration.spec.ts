// ABOUTME: Playwright test for OAuth user registration flow
// ABOUTME: Tests that users can register and obtain a UCAN token

import { test, expect } from '@playwright/test';

test.describe('OAuth Registration Flow', () => {
  test('should allow user to register and get UCAN token', async ({ page }) => {
    // Navigate to the OAuth client page
    await page.goto('/nostr-client-oauth-ndk.html');

    // Wait for page to load
    await expect(page.locator('h1')).toContainText('Keycast Nostr Client');

    // Click "New User (Register)" button
    await page.click('#btnRegister');

    // Wait for registration form to appear
    await expect(page.locator('#registerForm')).toBeVisible();

    // Generate unique email for this test
    const timestamp = Date.now();
    const email = `test-${timestamp}@example.com`;
    const password = 'testpass123';

    // Fill in registration form
    await page.fill('#registerEmail', email);
    await page.fill('#registerPassword', password);

    // Click register button
    await page.click('#btnDoRegister');

    // Wait for OAuth flow to complete and app section to become visible
    await expect(page.locator('#appSection')).toBeVisible({ timeout: 10000 });

    // Verify user identity section is shown
    await expect(page.locator('#userPubkey')).toBeVisible();
    await expect(page.locator('#userBunker')).toBeVisible();

    // Verify public key is displayed (should be 64 hex characters)
    const pubkey = await page.locator('#userPubkey').textContent();
    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);

    // Verify bunker URL is displayed
    const bunkerUrl = await page.locator('#userBunker').textContent();
    expect(bunkerUrl).toMatch(/^bunker:\/\/[0-9a-f]{64}\?relay=/);
  });

  test('should show error for invalid email', async ({ page }) => {
    await page.goto('/nostr-client-oauth-ndk.html');

    await page.click('#btnRegister');
    await expect(page.locator('#registerForm')).toBeVisible();

    // Try to register without email
    await page.fill('#registerPassword', 'testpass123');
    await page.click('#btnDoRegister');

    // Should show error
    await expect(page.locator('#authStatus .error')).toBeVisible({ timeout: 5000 });
  });

  test('should show error for missing password', async ({ page }) => {
    await page.goto('/nostr-client-oauth-ndk.html');

    await page.click('#btnRegister');
    await expect(page.locator('#registerForm')).toBeVisible();

    // Try to register without password
    await page.fill('#registerEmail', 'test@example.com');
    await page.click('#btnDoRegister');

    // Should show error
    await expect(page.locator('#authStatus .error')).toBeVisible({ timeout: 5000 });
  });
});
