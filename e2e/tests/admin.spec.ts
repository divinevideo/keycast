import { test, expect } from "@playwright/test";
import { registerAndVerify, parseCookieValue } from "../helpers/auth";
import { registerAdmin } from "../helpers/admin";
import {
  addSupportAdmin,
  removeSupportAdmin,
  clearSupportAdmins,
} from "../helpers/redis";

test.describe("Support admin management", () => {
  test.afterEach(async () => {
    await clearSupportAdmins();
  });

  test("non-admin gets is_admin: false", async ({ request }) => {
    const email = `e2e-nonadmin-${Date.now()}@test.local`;
    const { cookie } = await registerAndVerify(request, email, "TestPass123!");
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    const res = await request.get("/api/admin/status", {
      headers: { Cookie: sessionCookie },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.is_admin).toBe(false);
    expect(body.role).toBeNull();
  });

  test("full admin gets role: full", async ({ request }) => {
    const { cookie } = await registerAdmin(request);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    const res = await request.get("/api/admin/status", {
      headers: { Cookie: sessionCookie },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.is_admin).toBe(true);
    expect(body.role).toBe("full");
  });

  test("full admin can list support admins", async ({ request }) => {
    const { cookie } = await registerAdmin(request);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    const res = await request.get("/api/admin/support-admins", {
      headers: { Cookie: sessionCookie },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.admins).toEqual([]);
  });

  test("full admin can add and remove support admins", async ({ request }) => {
    const { cookie } = await registerAdmin(request);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    const targetPubkey =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Add support admin
    const addRes = await request.post("/api/admin/support-admins", {
      headers: { Cookie: sessionCookie },
      data: { identifier: targetPubkey },
    });
    expect(addRes.status()).toBe(200);
    const addBody = await addRes.json();
    expect(addBody.pubkey).toBe(targetPubkey);
    expect(addBody.added).toBe(true);

    // Verify it appears in the list
    const listRes = await request.get("/api/admin/support-admins", {
      headers: { Cookie: sessionCookie },
    });
    expect(listRes.status()).toBe(200);
    const listBody = await listRes.json();
    expect(listBody.admins.map((a: any) => a.pubkey)).toContain(targetPubkey);

    // Remove support admin
    const removeRes = await request.delete(
      `/api/admin/support-admins/${targetPubkey}`,
      {
        headers: { Cookie: sessionCookie },
      },
    );
    expect(removeRes.status()).toBe(200);
    const removeBody = await removeRes.json();
    expect(removeBody.removed).toBe(true);

    // Verify list is empty again
    const listRes2 = await request.get("/api/admin/support-admins", {
      headers: { Cookie: sessionCookie },
    });
    const listBody2 = await listRes2.json();
    expect(listBody2.admins).toEqual([]);
  });

  test("support admin via Redis gets role: support", async ({ request }) => {
    const email = `e2e-support-${Date.now()}@test.local`;
    const { cookie } = await registerAndVerify(request, email, "TestPass123!");
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Get this user's pubkey
    const accountRes = await request.get("/api/user/account", {
      headers: { Cookie: sessionCookie },
    });
    const account = await accountRes.json();
    const pubkey = account.public_key;

    // Add to Redis support_admins set
    await addSupportAdmin(pubkey);

    const res = await request.get("/api/admin/status", {
      headers: { Cookie: sessionCookie },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.is_admin).toBe(true);
    expect(body.role).toBe("support");
  });

  test("support admin can access user-lookup", async ({ request }) => {
    // Register a target user to look up
    const targetEmail = `e2e-target-${Date.now()}@test.local`;
    await registerAndVerify(request, targetEmail, "TestPass123!");

    // Register a support admin
    const email = `e2e-supadmin-${Date.now()}@test.local`;
    const { cookie } = await registerAndVerify(request, email, "TestPass123!");
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Get pubkey and add to Redis
    const accountRes = await request.get("/api/user/account", {
      headers: { Cookie: sessionCookie },
    });
    const account = await accountRes.json();
    await addSupportAdmin(account.public_key);

    // Look up the target user by email
    const lookupRes = await request.get(
      `/api/admin/user-lookup?q=${encodeURIComponent(targetEmail)}`,
      {
        headers: { Cookie: sessionCookie },
      },
    );
    expect(lookupRes.status()).toBe(200);

    const lookupBody = await lookupRes.json();
    expect(lookupBody.found).toBe(true);
    expect(lookupBody.user.email).toBe(targetEmail);
  });

  test("support admin cannot access full admin endpoints", async ({
    request,
  }) => {
    const email = `e2e-supnoaccess-${Date.now()}@test.local`;
    const { cookie } = await registerAndVerify(request, email, "TestPass123!");
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Get pubkey and make support admin
    const accountRes = await request.get("/api/user/account", {
      headers: { Cookie: sessionCookie },
    });
    const account = await accountRes.json();
    await addSupportAdmin(account.public_key);

    // Verify support role
    const statusRes = await request.get("/api/admin/status", {
      headers: { Cookie: sessionCookie },
    });
    const statusBody = await statusRes.json();
    expect(statusBody.role).toBe("support");

    // GET /admin/support-admins → 403
    const listRes = await request.get("/api/admin/support-admins", {
      headers: { Cookie: sessionCookie },
    });
    expect(listRes.status()).toBe(403);

    // GET /admin/token → 403
    const tokenRes = await request.get("/api/admin/token", {
      headers: { Cookie: sessionCookie },
    });
    expect(tokenRes.status()).toBe(403);
  });

  test("support-admin page redirects unauthenticated to login with redirect param", async ({
    page,
  }) => {
    await page.goto("http://localhost:3000/support-admin");

    // Should redirect to /login with redirect param
    await page.waitForURL(
      (url) =>
        url.pathname === "/login" &&
        url.searchParams.get("redirect") === "/support-admin",
    );
  });

  test("login redirects back to support-admin after authentication", async ({
    page,
    request,
  }) => {
    test.setTimeout(60000);

    // Register a support admin via API
    const email = `e2e-redirect-${Date.now()}@test.local`;
    const { cookie } = await registerAndVerify(request, email, "TestPass123!");
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Get pubkey and make support admin
    const accountRes = await request.get("/api/user/account", {
      headers: { Cookie: sessionCookie },
    });
    const account = await accountRes.json();
    await addSupportAdmin(account.public_key);

    // Visit /login?redirect=/support-admin and log in via form
    await page.goto("http://localhost:3000/login?redirect=/support-admin");
    await page.fill('input[type="email"]', email);
    await page.fill('input[type="password"]', "TestPass123!");
    await page.click('button[type="submit"]');

    // Should redirect back to /support-admin after login
    await page.waitForURL("http://localhost:3000/support-admin", {
      timeout: 15000,
    });
    await expect(page.locator("text=Support Admin")).toBeVisible({
      timeout: 10000,
    });
  });

  test("full admin can access support-admin page via browser", async ({
    page,
    request,
  }) => {
    test.setTimeout(60000);
    const { cookie } = await registerAdmin(request);
    const sessionValue = parseCookieValue(cookie);

    // Set only keycast_session (simulates email/password login, no keycastUserPubkey)
    await page.context().addCookies([
      {
        name: "keycast_session",
        value: sessionValue,
        domain: "localhost",
        path: "/",
      },
    ]);

    await page.goto("http://localhost:3000/support-admin");

    // Should stay on /support-admin and show admin UI
    await expect(page.locator("text=Support Admin")).toBeVisible({
      timeout: 10000,
    });
    await expect(page).toHaveURL("http://localhost:3000/support-admin");
  });
});
