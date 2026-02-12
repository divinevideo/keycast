import { createHash, randomBytes } from "node:crypto";
import { APIRequestContext } from "@playwright/test";

export interface PKCEChallenge {
  verifier: string;
  challenge: string;
  method: "S256";
}

export function generatePKCE(): PKCEChallenge {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge, method: "S256" };
}

export interface TokenResponse {
  bunker_url: string;
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  authorization_handle?: string;
  refresh_token?: string;
}

export async function exchangeCode(
  request: APIRequestContext,
  opts: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier?: string;
  },
): Promise<TokenResponse> {
  const res = await request.post("/api/oauth/token", {
    data: {
      grant_type: "authorization_code",
      code: opts.code,
      client_id: opts.clientId,
      redirect_uri: opts.redirectUri,
      ...(opts.codeVerifier ? { code_verifier: opts.codeVerifier } : {}),
    },
  });
  if (!res.ok()) {
    const body = await res.text();
    throw new Error(`Token exchange failed (${res.status()}): ${body}`);
  }
  return res.json();
}

export interface AuthorizeResponse {
  code: string;
  redirect_uri: string;
}

export async function apiAuthorize(
  request: APIRequestContext,
  cookie: string,
  opts: {
    clientId: string;
    redirectUri: string;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  },
): Promise<AuthorizeResponse> {
  const res = await request.post("/api/oauth/authorize", {
    headers: { Cookie: cookie },
    data: {
      client_id: opts.clientId,
      redirect_uri: opts.redirectUri,
      scope: opts.scope || "policy:full",
      approved: true,
      ...(opts.codeChallenge
        ? {
            code_challenge: opts.codeChallenge,
            code_challenge_method: opts.codeChallengeMethod || "S256",
          }
        : {}),
    },
    maxRedirects: 0,
  });

  // POST authorize may return 200 with JSON or 302 redirect
  if (res.status() === 200) {
    return res.json();
  }

  // Handle 302 redirect — extract code from Location header
  if (res.status() === 302) {
    const location = res.headers()["location"] || "";
    const url = new URL(location, "http://localhost");
    const code = url.searchParams.get("code");
    if (!code) {
      throw new Error(`Redirect had no code: ${location}`);
    }
    return { code, redirect_uri: location };
  }

  const body = await res.text();
  throw new Error(`Authorize failed (${res.status()}): ${body}`);
}

/** Complete OAuth flow: authorize + exchange, returns token response */
export async function completeOAuthFlow(
  request: APIRequestContext,
  cookie: string,
  opts?: {
    clientId?: string;
    redirectUri?: string;
    scope?: string;
    pkce?: PKCEChallenge;
  },
): Promise<TokenResponse> {
  const clientId = opts?.clientId || `e2e-test-${Date.now()}`;
  const redirectUri = opts?.redirectUri || "http://localhost:3456/callback.html";
  const pkce = opts?.pkce || generatePKCE();

  const { code } = await apiAuthorize(request, cookie, {
    clientId,
    redirectUri,
    scope: opts?.scope,
    codeChallenge: pkce.challenge,
    codeChallengeMethod: pkce.method,
  });

  return exchangeCode(request, {
    code,
    clientId,
    redirectUri,
    codeVerifier: pkce.verifier,
  });
}
