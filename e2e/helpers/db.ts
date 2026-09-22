import { execFileSync } from "node:child_process";
import { Client } from "pg";

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

export async function getVerificationToken(email: string): Promise<string> {
  for (let i = 0; i < 10; i++) {
    try {
      const token = await withDb(async (db) => {
        const result = await db.query(
          "SELECT email_verification_token FROM users WHERE email = $1",
          [email],
        );
        if (result.rows.length > 0 && result.rows[0].email_verification_token) {
          return result.rows[0].email_verification_token as string;
        }
        return null;
      });

      if (token) {
        return token;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes("ECONNRESET")) {
        throw error;
      }
    }

    await new Promise((r) => setTimeout(r, 300));
  }

  const fallbackToken = execFileSync(
    process.execPath,
    [
      "-e",
      `
        const { Client } = require("pg");
        (async () => {
          const client = new Client({ connectionString: process.env.DATABASE_URL });
          await client.connect();
          const result = await client.query(
            "SELECT email_verification_token FROM users WHERE email = $1",
            [process.env.TOKEN_LOOKUP_EMAIL],
          );
          process.stdout.write(result.rows[0]?.email_verification_token || "");
          await client.end();
        })().catch((error) => {
          console.error(error);
          process.exit(1);
        });
      `,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        DATABASE_URL: CONNECTION_STRING,
        TOKEN_LOOKUP_EMAIL: email,
      },
    },
  ).trim();

  if (fallbackToken) {
    return fallbackToken;
  }

  throw new Error(`Could not find verification token for ${email}`);
}

export async function getClaimConfirmationToken(claimToken: string): Promise<string> {
  for (let i = 0; i < 10; i++) {
    try {
      const token = await withDb(async (db) => {
        const result = await db.query(
          "SELECT confirmation_token FROM account_claim_tokens WHERE token = $1",
          [claimToken],
        );
        if (result.rows.length > 0 && result.rows[0].confirmation_token) {
          return result.rows[0].confirmation_token as string;
        }
        return null;
      });

      if (token) {
        return token;
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
