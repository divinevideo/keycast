import { test, expect } from "@playwright/test";
import { parseCookieValue } from "../helpers/auth";
import { registerAdmin } from "../helpers/admin";

test.describe("Account claim flow", () => {
  test("preloaded user can claim via browser form", async ({
    page,
    request,
  }) => {
    test.setTimeout(60000);

    // 1. Register admin and get session cookie
    const { cookie } = await registerAdmin(request);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // 2. Preload a user via admin API
    const vineId = `e2e-vine-${Date.now()}`;
    const username = `claimuser${Date.now()}`;
    const displayName = "Test Claimer";

    const preloadRes = await request.post("/api/admin/preload-user", {
      headers: { Cookie: sessionCookie },
      data: { vine_id: vineId, username, display_name: displayName },
    });
    expect(preloadRes.status()).toBe(200);
    const preloadBody = await preloadRes.json();
    expect(preloadBody.pubkey).toMatch(/^[0-9a-f]{64}$/);

    // 3. Generate claim token via admin API
    const claimRes = await request.post("/api/admin/claim-tokens", {
      headers: { Cookie: sessionCookie },
      data: { vine_id: vineId },
    });
    expect(claimRes.status()).toBe(200);
    const claimBody = await claimRes.json();
    expect(claimBody.claim_url).toContain("/api/claim?token=");
    expect(claimBody.expires_at).toBeTruthy();

    // 4. Navigate browser to the claim URL
    await page.goto(claimBody.claim_url);

    // 5. Verify the HTML form renders with display name and username
    await expect(page.locator("h1")).toContainText("Claim Your Account", {
      timeout: 10000,
    });
    await expect(page.locator(".name")).toContainText(displayName);
    await expect(page.locator(".username")).toContainText(`@${username}`);

    // 6. Fill email and password fields, submit
    const claimEmail = `e2e-claimed-${Date.now()}@test.local`;
    const claimPassword = "ClaimPass123!";

    await page.fill('input[name="email"]', claimEmail);
    await page.fill('input[name="password"]', claimPassword);
    await page.fill('input[name="password_confirmation"]', claimPassword);
    await page.click('button[type="submit"]');

    // 7. Verify redirect to dashboard with session cookie set
    await page.waitForURL("http://localhost:3000/", { timeout: 15000 });

    const cookies = await page.context().cookies();
    const kcCookie = cookies.find((c) => c.name === "keycast_session");
    expect(kcCookie).toBeTruthy();

    // 8. Verify the user can now log in with email/password
    const loginRes = await request.post("/api/auth/login", {
      data: { email: claimEmail, password: claimPassword },
    });
    expect(loginRes.status()).toBe(200);
    const loginBody = await loginRes.json();
    expect(loginBody.success).toBe(true);
    expect(loginBody.pubkey).toBe(preloadBody.pubkey);
  });

  test("invalid claim token shows error page", async ({ page }) => {
    await page.goto("http://localhost:3000/api/claim?token=invalid-token-abc");
    await expect(page.locator("h1")).toContainText(
      "Invalid or Expired Link",
      { timeout: 10000 },
    );
  });

  test("claim form rejects mismatched passwords", async ({
    page,
    request,
  }) => {
    test.setTimeout(60000);

    const { cookie } = await registerAdmin(request);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    const vineId = `e2e-vine-mismatch-${Date.now()}`;
    const preloadRes = await request.post("/api/admin/preload-user", {
      headers: { Cookie: sessionCookie },
      data: {
        vine_id: vineId,
        username: `mismatch${Date.now()}`,
        display_name: "Mismatch Test",
      },
    });
    expect(preloadRes.status()).toBe(200);

    const claimRes = await request.post("/api/admin/claim-tokens", {
      headers: { Cookie: sessionCookie },
      data: { vine_id: vineId },
    });
    expect(claimRes.status()).toBe(200);
    const claimBody = await claimRes.json();

    await page.goto(claimBody.claim_url);
    await expect(page.locator("h1")).toContainText("Claim Your Account", {
      timeout: 10000,
    });

    await page.fill('input[name="email"]', `e2e-mismatch-${Date.now()}@test.local`);
    await page.fill('input[name="password"]', "Password123!");
    await page.fill('input[name="password_confirmation"]', "DifferentPass!");
    await page.click('button[type="submit"]');

    await expect(page.locator("#error")).toBeVisible({ timeout: 5000 });
    await expect(page.locator("#error")).toContainText(
      "Passwords do not match",
    );
  });
});
