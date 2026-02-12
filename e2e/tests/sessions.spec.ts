import { test, expect } from "@playwright/test";
import { registerAndVerify, parseCookieValue } from "../helpers/auth";
import {
  completeOAuthFlow,
  generatePKCE,
  apiAuthorize,
  exchangeCode,
} from "../helpers/oauth";

const CALLBACK_URL = "http://localhost:3456/callback.html";

async function setupOAuth(request: any) {
  const email = `e2e-sess-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.local`;
  const password = "TestPass123!";
  const { cookie } = await registerAndVerify(request, email, password);
  const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

  const token = await completeOAuthFlow(request, sessionCookie, {
    redirectUri: CALLBACK_URL,
  });

  return { token, sessionCookie };
}

test.describe("Session management", () => {
  test("list sessions after OAuth", async ({ request }) => {
    const { token, sessionCookie } = await setupOAuth(request);

    const res = await request.get("/api/user/sessions", {
      headers: { Cookie: sessionCookie },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.sessions).toBeInstanceOf(Array);
    expect(body.sessions.length).toBeGreaterThanOrEqual(1);

    // Find the session matching our bunker URL
    const bunkerUrl = new URL(token.bunker_url);
    const bunkerPubkey = bunkerUrl.hostname;
    const session = body.sessions.find(
      (s: any) => s.bunker_pubkey === bunkerPubkey,
    );
    expect(session).toBeTruthy();
  });

  test("revoke session", async ({ request }) => {
    const { token, sessionCookie } = await setupOAuth(request);

    // Get the bunker pubkey from the URL
    const bunkerUrl = new URL(token.bunker_url);
    const bunkerPubkey = bunkerUrl.hostname;

    // Revoke the session
    const revokeRes = await request.post("/api/user/sessions/revoke", {
      headers: { Cookie: sessionCookie },
      data: { bunker_pubkey: bunkerPubkey },
    });
    expect(revokeRes.status()).toBe(200);
    const revokeBody = await revokeRes.json();
    expect(revokeBody.success).toBe(true);

    // Session should no longer appear in list
    const listRes = await request.get("/api/user/sessions", {
      headers: { Cookie: sessionCookie },
    });
    const listBody = await listRes.json();
    const found = listBody.sessions.find(
      (s: any) => s.bunker_pubkey === bunkerPubkey,
    );
    expect(found).toBeUndefined();
  });

  test("new token exchange fails after revoke", async ({ request }) => {
    const email = `e2e-revoke-sign-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.local`;
    const password = "TestPass123!";
    const { cookie } = await registerAndVerify(request, email, password);
    const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

    const clientId = `e2e-revoke-${Date.now()}`;
    const pkce = generatePKCE();

    // Complete first OAuth flow
    const token = await completeOAuthFlow(request, sessionCookie, {
      clientId,
      redirectUri: CALLBACK_URL,
    });

    // Revoke the session
    const bunkerUrl = new URL(token.bunker_url);
    const bunkerPubkey = bunkerUrl.hostname;
    const revokeRes = await request.post("/api/user/sessions/revoke", {
      headers: { Cookie: sessionCookie },
      data: { bunker_pubkey: bunkerPubkey },
    });
    expect(revokeRes.status()).toBe(200);

    // Get a new authorization code for same client
    const pkce2 = generatePKCE();
    const { code } = await apiAuthorize(request, sessionCookie, {
      clientId,
      redirectUri: CALLBACK_URL,
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: pkce2.method,
    });

    // Exchange new code — should get a fresh token with new bunker
    const token2 = await exchangeCode(request, {
      code,
      clientId,
      redirectUri: CALLBACK_URL,
      codeVerifier: pkce2.verifier,
    });

    // New token should work with a different bunker pubkey
    const newBunkerUrl = new URL(token2.bunker_url);
    expect(newBunkerUrl.hostname).not.toBe(bunkerPubkey);

    // New token should allow signing
    const signRes = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token2.access_token}` },
      data: { method: "get_public_key", params: [] },
    });
    expect(signRes.status()).toBe(200);
  });
});
