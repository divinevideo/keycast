import { createHash } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { Client } from "pg";
import { getDeliveredToken } from "./emails";

const CONNECTION_STRING =
  process.env.DATABASE_URL || "postgres://postgres:password@localhost/keycast";

export async function withDb<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: CONNECTION_STRING });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

export async function getClaimConfirmationToken(request: APIRequestContext, claimToken: string): Promise<string> {
  for (let i = 0; i < 10; i++) {
    try {
      const email = await withDb((db) => findClaimDeliveryEmail(db, claimToken));

      if (email) {
        return await getDeliveredToken(request, { email, pathname: "/api/claim/confirm" });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes("ECONNRESET")) {
        throw error;
      }
    }

    await new Promise((r) => setTimeout(r, 300));
  }

  throw new Error("Could not find claim confirmation token");
}

export async function findClaimDeliveryEmail(db: Pick<Client, "query">, claimToken: string): Promise<string | undefined> {
  const claimHash = createHash("sha256").update(claimToken).digest("hex");
  const result = await db.query(
    "SELECT pending_email FROM account_claim_tokens WHERE token = $1",
    [claimHash],
  );
  return result.rows[0]?.pending_email;
}

export async function markUserAtprotoReady(
  pubkey: string,
  did: string,
  tenantId?: number,
): Promise<void> {
  await withDb(async (db) => {
    if (tenantId === undefined) {
      await db.query(
        `UPDATE users
         SET atproto_enabled = true,
             atproto_state = 'ready',
             atproto_did = $1,
             updated_at = NOW()
         WHERE pubkey = $2`,
        [did, pubkey],
      );
      return;
    }

    await db.query(
      `UPDATE users
       SET atproto_enabled = true,
           atproto_state = 'ready',
           atproto_did = $1,
           updated_at = NOW()
       WHERE pubkey = $2
         AND tenant_id = $3`,
      [did, pubkey, tenantId],
    );
  });
}

export async function addRegisteredClient(
  clientId: string,
  redirectUris: string[],
  tenantId = 1,
): Promise<void> {
  await withDb(async (db) => {
    await db.query(
      `INSERT INTO registered_clients (client_id, allowed_redirect_uris, tenant_id, created_at, updated_at)
       VALUES ($1, $2::text[], $3, NOW(), NOW())
       ON CONFLICT (client_id, tenant_id)
       DO UPDATE SET allowed_redirect_uris = EXCLUDED.allowed_redirect_uris,
                     updated_at = NOW()`,
      [clientId, redirectUris, tenantId],
    );
  });
}

export async function deleteRegisteredClient(
  clientId: string,
  tenantId = 1,
): Promise<void> {
  await withDb(async (db) => {
    await db.query(
      "DELETE FROM registered_clients WHERE client_id = $1 AND tenant_id = $2",
      [clientId, tenantId],
    );
  });
}
