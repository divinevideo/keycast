import path from "node:path";
import { spawn } from "node:child_process";
import { expect, request as playwrightRequest, test } from "@playwright/test";
import { parseCookieValue, registerAndVerify } from "../helpers/auth";
import {
  atprotoAuthorize,
  atprotoExchangeCode,
  atprotoPar,
  completeOAuthFlow,
  createDpopProof,
  generateDpopKeyMaterial,
  generatePKCE,
} from "../helpers/oauth";
import { markUserAtprotoReady } from "../helpers/db";
import { startKeycastProcess, stopKeycastProcess } from "../helpers/keycast-process";

async function setupAtprotoReadyUser(requestCtx: any): Promise<{ cookie: string }> {
  const email = `e2e-atproto-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@test.local`;
  const { cookie } = await registerAndVerify(requestCtx, email, "TestPass123!");
  const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

  const accountRes = await requestCtx.get("/api/user/account", {
    headers: { Cookie: sessionCookie },
  });
  if (!accountRes.ok()) {
    throw new Error(
      `Failed to fetch account for ATProto setup (${accountRes.status()}): ${await accountRes.text()}`,
    );
  }
  const account = await accountRes.json();
  await markUserAtprotoReady(account.public_key, `did:plc:${Date.now()}atproto`);

  return { cookie: sessionCookie };
}

function decodeJwtPayload(token: string): Record<string, any> {
  const payload = token.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

test.describe("OAuth security regressions", () => {
  let atprotoServer: any;
  let atprotoApi: any;

  test.beforeAll(async () => {
    atprotoServer = await startKeycastProcess({
      port: 3410,
      env: {
        ENABLE_TENANT_AUTO_PROVISIONING: "true",
      },
    });
    atprotoApi = await playwrightRequest.newContext({
      baseURL: "http://localhost:3410",
    });
  });

  test.afterAll(async () => {
    await atprotoApi?.dispose();
    await stopKeycastProcess(atprotoServer);
  });

  test("ATProto OAuth code exchange returns DPoP-bound tokens", async () => {
    const { cookie } = await setupAtprotoReadyUser(atprotoApi);
    const pkce = generatePKCE();
    const dpopKey = generateDpopKeyMaterial();
    const clientId = "https://client.example";
    const redirectUri = "https://client.example/callback";

    const par = await atprotoPar(atprotoApi, {
      dpopKey,
      clientId,
      redirectUri,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: pkce.method,
    });

    const authorized = await atprotoAuthorize(atprotoApi, {
      cookie,
      requestUri: par.body.request_uri,
    });

    const token = await atprotoExchangeCode(atprotoApi, {
      dpopKey,
      nonce: par.nonce,
      code: authorized.code,
      clientId,
      redirectUri,
      codeVerifier: pkce.verifier,
    });

    expect(token.body.token_type).toBe("DPoP");
    expect(token.body.scope).toBe("atproto");
    const payload = decodeJwtPayload(token.body.access_token);
    expect(payload.cnf?.jkt).toBe(dpopKey.jkt);
  });

  test("ATProto OAuth rejects missing and replayed DPoP proofs", async () => {
    const pkce = generatePKCE();
    const formBody = new URLSearchParams({
      client_id: "https://client.example",
      redirect_uri: "https://client.example/callback",
      scope: "atproto",
      state: "state-replay",
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
    }).toString();

    const missingProof = await atprotoApi.post("/api/atproto/oauth/par", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      data: formBody,
    });
    expect(missingProof.status()).toBe(400);

    const dpopKey = generateDpopKeyMaterial();
    const fixedJti = `dpop-fixed-${Date.now()}`;
    const firstProof = createDpopProof(dpopKey, {
      method: "POST",
      htu: `${new URL(process.env.API_URL || "http://localhost:3000").origin}/api/atproto/oauth/par`,
      jti: fixedJti,
      iat: Math.floor(Date.now() / 1000),
    });

    const first = await atprotoApi.post("/api/atproto/oauth/par", {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: firstProof,
      },
      data: formBody,
    });
    expect(first.status()).toBe(200);

    const replay = await atprotoApi.post("/api/atproto/oauth/par", {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: firstProof,
      },
      data: formBody,
    });
    expect(replay.status()).toBe(400);
    expect(await replay.text()).toContain("already been used");
  });

  test("Cross-tenant resource access is rejected for OAuth tokens", async () => {
    const isolatedPort = 3411;
    const server = await startKeycastProcess({
      port: isolatedPort,
      env: {
        ENABLE_TENANT_AUTO_PROVISIONING: "false",
      },
    });

    try {
      const isolatedApi = await playwrightRequest.newContext({
        baseURL: `http://localhost:${isolatedPort}`,
      });

      const email = `e2e-cross-tenant-${Date.now()}@test.local`;
      const { cookie } = await registerAndVerify(isolatedApi, email, "TestPass123!");
      const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;
      const token = await completeOAuthFlow(isolatedApi, sessionCookie, {
        clientId: `e2e-cross-tenant-client-${Date.now()}`,
      });

      const crossTenant = await isolatedApi.post("/api/nostr", {
        headers: {
          Authorization: `Bearer ${token.access_token}`,
          Host: "tenant-b.localhost",
        },
        data: { method: "get_public_key", params: [] },
      });

      expect([400, 401, 403]).toContain(crossTenant.status());
    } finally {
      await stopKeycastProcess(server);
    }
  });

  test("Open OAuth permits unregistered clients", async ({ request }) => {
    // TODO(#282): Flip this expectation when redirect-flow OAuth requires registered clients.
    const res = await request.get(
      `/api/oauth/authorize?client_id=unknown-security-client&redirect_uri=${encodeURIComponent(
        "http://localhost:3456/callback.html",
      )}&scope=policy:full`,
    );
    expect(res.status()).toBe(200);

    const body = await res.text();
    expect(body).toContain("<h1>Sign in</h1>");
    expect(body).toContain("unknown-security-client");
  });

  test("Production mode fails closed when email provider is missing", async () => {
    const workspaceRoot = path.resolve(__dirname, "..", "..");
    const binaryPath =
      process.env.KEYCAST_BINARY || path.join(workspaceRoot, "target", "debug", "keycast");

    let child: ReturnType<typeof spawn> | null = null;
    let output = "";

    try {
      child = spawn(binaryPath, [], {
        cwd: workspaceRoot,
        env: {
          ...process.env,
          DATABASE_URL:
            process.env.DATABASE_URL || "postgres://postgres:password@localhost/keycast",
          REDIS_URL: process.env.REDIS_URL || "redis://localhost:16379",
          MASTER_KEY_PATH: process.env.MASTER_KEY_PATH || path.join(workspaceRoot, "master.key"),
          SERVER_NSEC:
            process.env.SERVER_NSEC ||
            "0000000000000000000000000000000000000000000000000000000000000001",
          BUNKER_RELAYS: process.env.BUNKER_RELAYS || "ws://localhost:8080",
          ALLOWED_ORIGINS:
            process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://localhost:5173",
          ALLOWED_TENANT_DOMAINS: process.env.ALLOWED_TENANT_DOMAINS || "localhost",
          RUST_ENV: "production",
          SENDGRID_API_KEY: "",
          DISABLE_EMAILS: "",
          PORT: "3413",
        },
        stdio: "pipe",
      });

      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
      });
      child.stderr.on("data", (chunk) => {
        output += chunk.toString();
      });

      const exitCode = await Promise.race<number | null>([
        new Promise<number | null>((resolve) => {
          child?.once("close", resolve);
        }),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 15_000)),
      ]);

      expect(exitCode).not.toBeNull();
      expect(exitCode).not.toBe(0);
      expect(output).toContain("SENDGRID_API_KEY required in production");
    } finally {
      await stopKeycastProcess(child);
    }
  });
});
