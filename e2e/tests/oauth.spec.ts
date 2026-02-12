import { test, expect } from "@playwright/test";
import { registerAndVerify, parseCookieValue } from "../helpers/auth";
import {
  generatePKCE,
  apiAuthorize,
  exchangeCode,
  completeOAuthFlow,
} from "../helpers/oauth";

const CALLBACK_URL = "http://localhost:3456/callback.html";

const PASSWORD = "TestPass123!";

/** Set up a verified user and return the session cookie header */
async function setupUser(request: any) {
  const email = `e2e-oauth-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.local`;
  const { cookie } = await registerAndVerify(request, email, PASSWORD);
  return { email, cookie: `keycast_session=${parseCookieValue(cookie)}` };
}

test.describe("OAuth consent flow", () => {
  test("consent approve redirects with code", async ({
    page,
    request,
    context,
  }) => {
    const { cookie } = await setupUser(request);
    const sessionValue = cookie.replace("keycast_session=", "");

    const baseURL = process.env.API_URL || "http://localhost:3000";
    const url = new URL(baseURL);
    await context.addCookies([
      {
        name: "keycast_session",
        value: sessionValue,
        domain: url.hostname,
        path: "/",
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);

    const authorizeURL = `/api/oauth/authorize?client_id=e2e-test&redirect_uri=${encodeURIComponent(CALLBACK_URL)}&scope=policy:full`;
    await page.goto(authorizeURL);

    await expect(page.locator("h1")).toContainText("Authorize");
    await expect(page.locator("#display_name")).toBeVisible();
    await page.locator(".btn_approve").click();

    await page.waitForURL(/localhost:3456\/callback\.html\?code=/, {
      timeout: 10000,
    });

    await expect(page.locator("#status")).toHaveText("Authorization successful");
    const code = await page.locator("#code").textContent();
    expect(code).toBeTruthy();
    expect(code!.length).toBeGreaterThan(0);
  });

  test("consent deny redirects with error", async ({
    page,
    request,
    context,
  }) => {
    const { cookie } = await setupUser(request);
    const sessionValue = cookie.replace("keycast_session=", "");

    const baseURL = process.env.API_URL || "http://localhost:3000";
    const url = new URL(baseURL);
    await context.addCookies([
      {
        name: "keycast_session",
        value: sessionValue,
        domain: url.hostname,
        path: "/",
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);

    const authorizeURL = `/api/oauth/authorize?client_id=e2e-deny-test&redirect_uri=${encodeURIComponent(CALLBACK_URL)}&scope=policy:full`;
    await page.goto(authorizeURL);

    await expect(page.locator("h1")).toContainText("Authorize");
    await page.locator(".btn_deny").click();

    await page.waitForURL(/localhost:3456\/callback\.html\?error=access_denied/, {
      timeout: 10000,
    });

    await expect(page.locator("#status")).toHaveText("Authorization failed");
    await expect(page.locator("#error")).toHaveText("access_denied");
  });

  test("full PKCE flow", async ({ request }) => {
    const { cookie } = await setupUser(request);
    const pkce = generatePKCE();

    const { code } = await apiAuthorize(request, cookie, {
      clientId: "e2e-pkce",
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: pkce.method,
    });
    expect(code).toBeTruthy();

    const token = await exchangeCode(request, {
      code,
      clientId: "e2e-pkce",
      redirectUri: CALLBACK_URL,
      codeVerifier: pkce.verifier,
    });
    expect(token.bunker_url).toBeTruthy();
    expect(token.access_token).toBeTruthy();
  });

  test("wrong code_verifier fails", async ({ request }) => {
    const { cookie } = await setupUser(request);
    const pkce = generatePKCE();

    const { code } = await apiAuthorize(request, cookie, {
      clientId: "e2e-pkce-bad",
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: pkce.method,
    });

    const res = await request.post("/api/oauth/token", {
      data: {
        grant_type: "authorization_code",
        code,
        client_id: "e2e-pkce-bad",
        redirect_uri: CALLBACK_URL,
        code_verifier: "wrong-verifier-value",
      },
    });
    expect(res.status()).toBe(400);
  });

  test("wrong redirect_uri on exchange fails", async ({ request }) => {
    const { cookie } = await setupUser(request);
    const pkce = generatePKCE();

    const { code } = await apiAuthorize(request, cookie, {
      clientId: "e2e-redir",
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: pkce.method,
    });

    const res = await request.post("/api/oauth/token", {
      data: {
        grant_type: "authorization_code",
        code,
        client_id: "e2e-redir",
        redirect_uri: "http://evil.example.com/callback",
        code_verifier: pkce.verifier,
      },
    });
    expect(res.status()).toBe(400);
  });

  test("bunker_url format is valid", async ({ request }) => {
    const { cookie } = await setupUser(request);
    const token = await completeOAuthFlow(request, cookie, {
      redirectUri: CALLBACK_URL,
    });

    expect(token.bunker_url).toMatch(/^bunker:\/\//);

    const url = new URL(token.bunker_url);
    // pubkey is the hostname (64-char hex)
    expect(url.hostname).toMatch(/^[0-9a-f]{64}$/);
    // Must have at least one relay
    const relays = url.searchParams.getAll("relay");
    expect(relays.length).toBeGreaterThan(0);
    for (const relay of relays) {
      expect(relay).toMatch(/^wss?:\/\//);
    }
    // Must have a secret
    const secret = url.searchParams.get("secret");
    expect(secret).toBeTruthy();
    expect(secret!.length).toBeGreaterThan(0);
  });

  test("auto-approve repeat origin", async ({ request }) => {
    const { cookie } = await setupUser(request);
    const clientId = `e2e-repeat-${Date.now()}`;

    // First authorization — explicit approval
    const pkce1 = generatePKCE();
    const { code: code1 } = await apiAuthorize(request, cookie, {
      clientId,
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce1.challenge,
      codeChallengeMethod: pkce1.method,
    });
    expect(code1).toBeTruthy();

    // Exchange to finalize the authorization
    await exchangeCode(request, {
      code: code1,
      clientId,
      redirectUri: CALLBACK_URL,
      codeVerifier: pkce1.verifier,
    });

    // Second authorization for same origin — should auto-approve
    const pkce2 = generatePKCE();
    const { code: code2 } = await apiAuthorize(request, cookie, {
      clientId,
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: pkce2.method,
    });
    expect(code2).toBeTruthy();

    // Should also be exchangeable
    const token2 = await exchangeCode(request, {
      code: code2,
      clientId,
      redirectUri: CALLBACK_URL,
      codeVerifier: pkce2.verifier,
    });
    expect(token2.bunker_url).toBeTruthy();
  });

  test("no consent after logout and relogin", async ({ request }) => {
    const { email, cookie } = await setupUser(request);
    const clientId = `e2e-relogin-${Date.now()}`;

    // First authorization — explicit approval
    const pkce1 = generatePKCE();
    const { code: code1 } = await apiAuthorize(request, cookie, {
      clientId,
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce1.challenge,
      codeChallengeMethod: pkce1.method,
    });
    await exchangeCode(request, {
      code: code1,
      clientId,
      redirectUri: CALLBACK_URL,
      codeVerifier: pkce1.verifier,
    });

    // Logout
    const logoutRes = await request.post("/api/auth/logout", {
      headers: { Cookie: cookie },
    });
    expect(logoutRes.status()).toBe(200);

    // Login again — new session
    const loginRes = await request.post("/api/auth/login", {
      data: { email, password: PASSWORD },
    });
    expect(loginRes.status()).toBe(200);
    const loginCookie = `keycast_session=${parseCookieValue(loginRes.headers()["set-cookie"])}`;

    // Second authorization with new session — should auto-approve (no consent)
    const pkce2 = generatePKCE();
    const { code: code2 } = await apiAuthorize(request, loginCookie, {
      clientId,
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: pkce2.method,
    });
    expect(code2).toBeTruthy();

    const token = await exchangeCode(request, {
      code: code2,
      clientId,
      redirectUri: CALLBACK_URL,
      codeVerifier: pkce2.verifier,
    });
    expect(token.bunker_url).toBeTruthy();
  });
});
