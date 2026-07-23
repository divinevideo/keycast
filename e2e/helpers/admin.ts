import { APIRequestContext } from "@playwright/test";
import { getVerificationToken, withDb } from "./db";

export const ADMIN_SECRET_KEY =
  "6d84196f84e681d76f75c149c79e0375ecefae480a355130d0642a1e7c7bab44";
export const ADMIN_PUBKEY =
  "25fa07621969c92191feb4433fca94fdb500f2b445fd4f017c0a332ceecbf813";

const ADMIN_EMAIL = "e2e-admin-fixed@test.local";
const ADMIN_PASSWORD = "AdminPass123!";

async function verifyAdminEmail(
  request: APIRequestContext,
): Promise<{ cookie: string }> {
  const token = await getVerificationToken(ADMIN_EMAIL);

  for (let attempt = 0; attempt < 10; attempt++) {
    const verifyRes = await request.post("/api/auth/verify-email", {
      data: { token },
    });
    if (!verifyRes.ok()) {
      const body = await verifyRes.text();
      throw new Error(
        `Admin email verification failed (${verifyRes.status()}): ${body}`,
      );
    }

    const body = await verifyRes.json();
    if (body.status === "processing") {
      await new Promise((r) => setTimeout(r, 500));
      continue;
    }

    const setCookie = verifyRes.headers()["set-cookie"];
    if (!setCookie?.includes("keycast_session=")) {
      throw new Error("No keycast_session cookie in verify-email response");
    }

    return { cookie: setCookie };
  }

  throw new Error("Admin email verification timed out (password hash not ready)");
}

export async function registerAdmin(
  request: APIRequestContext,
): Promise<{ cookie: string }> {
  const registerRes = await request.post("/api/auth/register", {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD, nsec: ADMIN_SECRET_KEY },
  });

  // 409 means already registered (idempotent for re-runs)
  if (registerRes.status() === 409) {
    const loginRes = await request.post("/api/auth/login", {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    });
    if (loginRes.status() === 403) {
      return verifyAdminEmail(request);
    }
    if (!loginRes.ok()) {
      const body = await loginRes.text();
      throw new Error(`Admin login failed (${loginRes.status()}): ${body}`);
    }
    const setCookie = loginRes.headers()["set-cookie"];
    if (!setCookie?.includes("keycast_session=")) {
      throw new Error("No keycast_session cookie in login response");
    }
    return { cookie: setCookie };
  }

  if (!registerRes.ok()) {
    const body = await registerRes.text();
    throw new Error(
      `Admin registration failed (${registerRes.status()}): ${body}`,
    );
  }

  return verifyAdminEmail(request);
}

export async function getAdminTenantId(): Promise<number> {
  return withDb(async (db) => {
    const result = await db.query(
      "SELECT tenant_id FROM users WHERE pubkey = $1",
      [ADMIN_PUBKEY],
    );
    const tenantId = result.rows[0]?.tenant_id;
    if (tenantId === undefined) {
      throw new Error(`Admin user ${ADMIN_PUBKEY} was not found`);
    }
    return tenantId;
  });
}
