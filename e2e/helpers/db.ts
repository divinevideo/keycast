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
  return withDb(async (db) => {
    for (let i = 0; i < 10; i++) {
      const result = await db.query(
        "SELECT email_verification_token FROM users WHERE email = $1",
        [email],
      );
      if (result.rows.length > 0 && result.rows[0].email_verification_token) {
        return result.rows[0].email_verification_token as string;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error(`Could not find verification token for ${email}`);
  });
}
