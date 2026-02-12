import { test, expect } from "@playwright/test";
import { registerAndVerify, parseCookieValue } from "../helpers/auth";

test.describe("Authentication flows", () => {
  test("register + verify + login", async ({ request }) => {
    const email = `e2e-auth-${Date.now()}@test.local`;
    const password = "TestPass123!";

    const { cookie } = await registerAndVerify(request, email, password);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Verify session from registration works
    const accountRes = await request.get("/api/user/account", {
      headers: { Cookie: sessionCookie },
    });
    expect(accountRes.status()).toBe(200);
    const account = await accountRes.json();
    expect(account.email).toBe(email);

    // Login with same credentials
    const loginRes = await request.post("/api/auth/login", {
      data: { email, password },
    });
    expect(loginRes.status()).toBe(200);
    const loginBody = await loginRes.json();
    expect(loginBody.success).toBe(true);
    expect(loginBody.pubkey).toMatch(/^[0-9a-f]{64}$/);

    // Login response should include session cookie
    const loginSetCookie = loginRes.headers()["set-cookie"];
    expect(loginSetCookie).toContain("keycast_session=");
  });

  test("duplicate email returns 409", async ({ request }) => {
    const email = `e2e-dup-${Date.now()}@test.local`;
    const password = "TestPass123!";

    await registerAndVerify(request, email, password);

    const res = await request.post("/api/auth/register", {
      data: { email, password },
    });
    expect(res.status()).toBe(409);
  });

  test("wrong password returns 401", async ({ request }) => {
    const email = `e2e-wrongpw-${Date.now()}@test.local`;
    const password = "TestPass123!";

    await registerAndVerify(request, email, password);

    const res = await request.post("/api/auth/login", {
      data: { email, password: "WrongPassword!" },
    });
    expect(res.status()).toBe(401);
  });

  test("login before verify returns 403", async ({ request }) => {
    const email = `e2e-noverify-${Date.now()}@test.local`;
    const password = "TestPass123!";

    // Register but don't verify
    const registerRes = await request.post("/api/auth/register", {
      data: { email, password },
    });
    expect(registerRes.ok()).toBe(true);

    // Wait for bcrypt
    await new Promise((r) => setTimeout(r, 1500));

    const loginRes = await request.post("/api/auth/login", {
      data: { email, password },
    });
    expect(loginRes.status()).toBe(403);
  });

  test("logout clears session cookie", async ({ request }) => {
    const email = `e2e-logout-${Date.now()}@test.local`;
    const password = "TestPass123!";

    const { cookie } = await registerAndVerify(request, email, password);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Verify session works
    const accountRes = await request.get("/api/user/account", {
      headers: { Cookie: sessionCookie },
    });
    expect(accountRes.status()).toBe(200);

    // Logout should succeed and set cookie with Max-Age=0 to clear it
    const logoutRes = await request.post("/api/auth/logout", {
      headers: { Cookie: sessionCookie },
    });
    expect(logoutRes.status()).toBe(200);
    const logoutBody = await logoutRes.json();
    expect(logoutBody.success).toBe(true);

    // Verify logout response clears the cookie
    const setCookie = logoutRes.headers()["set-cookie"];
    expect(setCookie).toContain("Max-Age=0");
  });

  test("change password", async ({ request }) => {
    const email = `e2e-chpw-${Date.now()}@test.local`;
    const oldPassword = "OldPass123!";
    const newPassword = "NewPass456!";

    const { cookie } = await registerAndVerify(request, email, oldPassword);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    // Change password
    const changeRes = await request.post("/api/user/change-password", {
      headers: { Cookie: sessionCookie },
      data: { current_password: oldPassword, new_password: newPassword },
    });
    expect(changeRes.status()).toBe(200);

    // Login with new password succeeds
    const newLoginRes = await request.post("/api/auth/login", {
      data: { email, password: newPassword },
    });
    expect(newLoginRes.status()).toBe(200);

    // Login with old password fails
    const oldLoginRes = await request.post("/api/auth/login", {
      data: { email, password: oldPassword },
    });
    expect(oldLoginRes.status()).toBe(401);
  });
});
