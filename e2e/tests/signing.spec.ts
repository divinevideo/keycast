import { test, expect } from "@playwright/test";
import { registerAndVerify, parseCookieValue } from "../helpers/auth";
import { completeOAuthFlow } from "../helpers/oauth";
import { connectToBunker } from "../helpers/nip46";

const CALLBACK_URL = "http://localhost:3456/callback.html";

async function setupOAuth(request: any) {
  const email = `e2e-sign-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.local`;
  const password = "TestPass123!";
  const { cookie } = await registerAndVerify(request, email, password);
  const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

  const token = await completeOAuthFlow(request, sessionCookie, {
    redirectUri: CALLBACK_URL,
  });

  return { token, sessionCookie };
}

test.describe("HTTP RPC signing", () => {
  test("get_public_key via RPC", async ({ request }) => {
    const { token } = await setupOAuth(request);

    const res = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      data: { method: "get_public_key", params: [] },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.error).toBeUndefined();
    expect(body.result).toMatch(/^[0-9a-f]{64}$/);
  });

  test("sign_event via RPC", async ({ request }) => {
    const { token } = await setupOAuth(request);

    // Get pubkey first
    const pkRes = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      data: { method: "get_public_key", params: [] },
    });
    const pubkey = (await pkRes.json()).result;

    // Build unsigned event
    const unsignedEvent = {
      kind: 1,
      content: "Hello from e2e test",
      tags: [],
      created_at: Math.floor(Date.now() / 1000),
      pubkey,
    };

    const res = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      data: { method: "sign_event", params: [unsignedEvent] },
    });
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.error).toBeUndefined();
    const signed = body.result;
    expect(signed.id).toMatch(/^[0-9a-f]{64}$/);
    expect(signed.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(signed.pubkey).toBe(pubkey);
    expect(signed.kind).toBe(1);
    expect(signed.content).toBe("Hello from e2e test");
  });

  test("nip44 roundtrip via RPC", async ({ request }) => {
    const { token } = await setupOAuth(request);

    // Get pubkey for encrypt-to-self
    const pkRes = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      data: { method: "get_public_key", params: [] },
    });
    const pubkey = (await pkRes.json()).result;

    const plaintext = "secret message for e2e test";

    // Encrypt
    const encRes = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      data: { method: "nip44_encrypt", params: [pubkey, plaintext] },
    });
    expect(encRes.status()).toBe(200);
    const encBody = await encRes.json();
    expect(encBody.error).toBeUndefined();
    const ciphertext = encBody.result;
    expect(ciphertext).toBeTruthy();
    expect(ciphertext).not.toBe(plaintext);

    // Decrypt
    const decRes = await request.post("/api/nostr", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      data: { method: "nip44_decrypt", params: [pubkey, ciphertext] },
    });
    expect(decRes.status()).toBe(200);
    const decBody = await decRes.json();
    expect(decBody.error).toBeUndefined();
    expect(decBody.result).toBe(plaintext);
  });
});

test.describe("NIP-46 relay signing", () => {
  test.setTimeout(120_000);

  test("get_public_key via relay", async ({ request }) => {
    const { token } = await setupOAuth(request);

    const client = await connectToBunker(token.bunker_url);
    try {
      const pubkey = await client.getPublicKey();
      expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      await client.close();
    }
  });

  test("sign_event via relay", async ({ request }) => {
    const { token } = await setupOAuth(request);

    const client = await connectToBunker(token.bunker_url);
    try {
      const pubkey = await client.getPublicKey();

      const event = {
        kind: 1,
        content: "Hello from NIP-46 e2e test",
        tags: [],
        created_at: Math.floor(Date.now() / 1000),
      };

      const signed = await client.signEvent(event);
      expect(signed.id).toMatch(/^[0-9a-f]{64}$/);
      expect(signed.sig).toMatch(/^[0-9a-f]{128}$/);
      expect(signed.pubkey).toBe(pubkey);
      expect(signed.kind).toBe(1);
      expect(signed.content).toBe("Hello from NIP-46 e2e test");
    } finally {
      await client.close();
    }
  });

  test("nip44 roundtrip via relay", async ({ request }) => {
    const { token } = await setupOAuth(request);

    const client = await connectToBunker(token.bunker_url);
    try {
      const pubkey = await client.getPublicKey();
      const plaintext = "secret relay message for e2e test";

      const ciphertext = await client.nip44Encrypt(pubkey, plaintext);
      expect(ciphertext).toBeTruthy();
      expect(ciphertext).not.toBe(plaintext);

      const decrypted = await client.nip44Decrypt(pubkey, ciphertext);
      expect(decrypted).toBe(plaintext);
    } finally {
      await client.close();
    }
  });
});
