import { withDb } from "./db";

/** Grant support admin to an existing user, in that user's tenant. */
export async function addSupportAdmin(pubkey: string) {
  return withDb(async (db) => {
    const user = await db.query("SELECT tenant_id FROM users WHERE pubkey = $1", [
      pubkey,
    ]);
    const tenantId = user.rows[0]?.tenant_id;
    if (tenantId === undefined) {
      throw new Error(`User ${pubkey} was not found`);
    }
    await db.query(
      `INSERT INTO support_admins (tenant_id, pubkey) VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [tenantId, pubkey],
    );
  });
}

export async function clearSupportAdmins() {
  return withDb((db) => db.query("DELETE FROM support_admins"));
}
