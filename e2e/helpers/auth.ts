import { APIRequestContext } from "@playwright/test";
import { getVerificationToken } from "./db";

interface VerifyResult {
  cookie: string;
}

export async function registerAndVerify(
  request: APIRequestContext,
  email: string,
  password: string,
): Promise<VerifyResult> {
  // Register the user
  const registerRes = await request.post("/api/auth/register", {
    data: { email, password },
  });
  if (!registerRes.ok()) {
    const body = await registerRes.text();
    throw new Error(`Registration failed (${registerRes.status()}): ${body}`);
  }

  // Wait for bcrypt worker to hash password
  await new Promise((r) => setTimeout(r, 1000));

  // Extract verification token from DB
  const token = await getVerificationToken(email);

  // Verify email - this sets the session cookie
  const verifyRes = await request.post("/api/auth/verify-email", {
    data: { token },
  });
  if (!verifyRes.ok()) {
    const body = await verifyRes.text();
    throw new Error(`Email verification failed (${verifyRes.status()}): ${body}`);
  }

  const setCookie = verifyRes.headers()["set-cookie"];
  if (!setCookie || !setCookie.includes("keycast_session=")) {
    throw new Error("No keycast_session cookie in verify-email response");
  }

  return { cookie: setCookie };
}

export function parseCookieValue(setCookie: string): string {
  const match = setCookie.match(/keycast_session=([^;]+)/);
  if (!match) throw new Error("Could not parse keycast_session value");
  return match[1];
}
