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
