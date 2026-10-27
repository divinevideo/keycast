import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { Client } from "pg";
import type { APIRequestContext } from "@playwright/test";
import { generatePKCE } from "./oauth";

const DATABASE_URL = "postgres://postgres:acceptance@localhost:5432/keycast_image_acceptance";
const BASE_URL = "http://localhost:3000";
const RELAY_URL = "ws://localhost:8080";
const OWNERSHIP_PATH = "/tmp/challenge-image-ownership.json";
const HEX64 = /^[a-f0-9]{64}$/;
const API_TIMEOUT = 15000;

export interface FixtureConfig {
  readonly nonce: string;
  readonly sourceSha: string;
  readonly daemonImageId: string;
  readonly namespaceOwnerId: string;
  readonly clientId: string;
  readonly databaseUrl: string;
  readonly baseUrl: string;
  readonly relayUrl: string;
  readonly bunkerRelays: string;
}
export interface PolicyFixture {
  readonly id: number;
  readonly slug: string;
  readonly scope: string;
  readonly displayName: string;
  readonly kind: "restricted" | "empty" | "intersection";
}
export interface PolicyFixtures {
  restricted: PolicyFixture;
  empty: PolicyFixture;
  intersection: PolicyFixture;
}
export interface SessionFixture {
  readonly cookie: string;
  readonly pubkey: string;
  readonly tenantId: number;
  readonly teamId: number;
}
export interface Grant {
  accessToken: string;
  refreshToken: string;
  bunkerUrl: string;
  scope: string;
  pubkey: string;
  authorizationId: number;
}
interface Database {
  query(sql: string, values?: any[]): Promise<{ rows: any[]; rowCount: number | null }>;
}
// A separate I/O factory lets pure contracts exercise the same guards and flow
// without opening sockets. The normal exported helpers use only the fixed I/O.
export interface FixtureIO {
  readOwnership(): Promise<unknown>;
  withDb<T>(operation: (db: Database) => Promise<T>): Promise<T>;
  pause(milliseconds: number): Promise<void>;
}
function requireFixture(value: unknown, category: string): asserts value {
  if (!value) throw new Error(`challenge_image:${category}`);
}
function validConfig(c: FixtureConfig): void {
  requireFixture(c && /^[a-f0-9]{32}$/.test(c.nonce) && /^[a-f0-9]{40}$/.test(c.sourceSha)
    && /^sha256:[a-f0-9]{64}$/.test(c.daemonImageId) && HEX64.test(c.namespaceOwnerId)
    && HEX64.test(c.clientId) && c.namespaceOwnerId !== c.clientId
    && c.databaseUrl === DATABASE_URL && c.baseUrl === BASE_URL && c.relayUrl === RELAY_URL
    && c.bunkerRelays === RELAY_URL, "ownership_config");
}
export function configFromEnvironment(env: NodeJS.ProcessEnv = process.env): FixtureConfig {
  const c = {
    nonce: env.CHALLENGE_IMAGE_NONCE!, sourceSha: env.CHALLENGE_IMAGE_SOURCE_SHA!,
    daemonImageId: env.CHALLENGE_IMAGE_DAEMON_IMAGE_ID!, namespaceOwnerId: env.CHALLENGE_IMAGE_NAMESPACE_OWNER_ID!,
    clientId: env.CHALLENGE_IMAGE_CLIENT_ID!, bunkerRelays: env.BUNKER_RELAYS!,
    databaseUrl: DATABASE_URL, baseUrl: BASE_URL, relayUrl: RELAY_URL,
  };
  validConfig(c);
  return Object.freeze(c);
}

// Task 3 supplies actual Node Playwright --list stdout for both configurations.
// This helper itself performs collection validation only, with no setup or I/O.
export function assertDiscoverySeparation(input: {
  defaultTestDir: string; dedicatedTestDir: string; defaultListing: string; dedicatedListing: string;
  defaultExitCode: number | null; dedicatedExitCode: number | null;
}): void {
  const normal = path.resolve(input.defaultTestDir), dedicated = path.resolve(input.dedicatedTestDir);
  const contains = (a: string, b: string) => {
    const relative = path.relative(a, b);
    return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
  };
  requireFixture(!contains(normal, dedicated) && !contains(dedicated, normal), "discovery_roots");
  requireFixture(input.defaultExitCode === 0 && input.dedicatedExitCode === 0, "discovery_exit");
  const listedFiles = (stdout: string): string[] => {
    const lines = stdout.split(/\r?\n/);
    const rows = lines.flatMap(line => {
      // Actual Node Playwright list output, with or without a project prefix.
      const row = line.match(/^\s+(?:\[[^\]\r\n]+\] › )?([^:\r\n]+\.spec\.ts):[1-9]\d*:[1-9]\d* › \S.*$/);
      return row ? [row[1]] : [];
    });
    const totals = lines.flatMap(line => {
      const total = line.match(/^Total: ([0-9]+) tests? in ([0-9]+) files?$/);
      return total ? [[Number(total[1]), Number(total[2])]] : [];
    });
    requireFixture(lines.filter(line => line === "Listing tests:").length === 1 && totals.length === 1
      && rows.length > 0 && totals[0][0] === rows.length && totals[0][1] === new Set(rows).size, "discovery_collection");
    return rows;
  };
  const isSuite = (file: string) => path.posix.basename(file) === "challenge-image.spec.ts";
  requireFixture(!listedFiles(input.defaultListing).some(isSuite)
    && listedFiles(input.dedicatedListing).some(isSuite), "discovery_suite");
}

// Focused contract for this client's plain COPY instructions, not a Docker
// builder. Callers supply Bun's actual local inputs plus runtime-read assets.
// Repository-relative paths keep the same location beneath / in the client.
export function assertClientPackaging(input: { dockerfile: string; requiredPaths: readonly string[] }): void {
  let workdir = "/";
  let copies: { source: string; destination: string; directory: boolean }[] = [];
  for (const raw of input.dockerfile.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("FROM ")) { workdir = "/"; copies = []; }
    if (line.startsWith("WORKDIR ")) workdir = path.posix.resolve(workdir, line.slice(8).trim());
    if (!line.startsWith("COPY ") || line.startsWith("COPY --from=")) continue;
    const parts = line.split(/\s+/).slice(1);
    const destination = parts.pop()!;
    requireFixture(parts.length > 0 && !/[\[\]"'\\*?]/.test(parts.join(" ") + destination)
      && !parts.some(source => source.startsWith("--"))
      && (parts.length === 1 || destination.endsWith("/")), "packaging_copy_format");
    for (const source of parts) {
      // Keep the narrow helper COPY boundary; never package the old auth/db
      // fallbacks or broad trees as a way to satisfy an incomplete graph.
      requireFixture(![".", "./", "e2e", "e2e/", "e2e/helpers", "e2e/helpers/", "e2e/helpers/auth.ts", "e2e/helpers/db.ts"].includes(source)
        && (!source.endsWith("/") || source === "e2e/challenge-image/"), "packaging_copy_scope");
      const directory = source.endsWith("/");
      copies.push({ source, directory, destination: path.posix.resolve(workdir, destination,
        !directory && destination.endsWith("/") ? path.posix.basename(source) : "") });
    }
  }
  requireFixture(input.requiredPaths.length > 0, "packaging_graph");
  for (const file of input.requiredPaths) {
    requireFixture(path.posix.normalize(file) === file && !path.posix.isAbsolute(file) && !file.startsWith("../")
      && !["e2e/helpers/auth.ts", "e2e/helpers/db.ts"].includes(file), "packaging_graph");
    const expected = "/" + file;
    requireFixture(copies.some(copy => copy.directory
      ? file.startsWith(copy.source) && path.posix.join(copy.destination, file.slice(copy.source.length)) === expected
      : copy.source === file && copy.destination === expected), "packaging_missing_file");
  }
}

const permissionSpecs = {
  restricted: [["challenge_actions", "{}"]],
  empty: [],
  intersection: [["challenge_actions", "{}"], ["allowed_kinds", '{"allowed_kinds":[31923]}']],
} as const;
type PermissionRow = { id: number; identifier: string; config: string };
const policyQuery = `SELECT p.id AS policy_id, p.slug, p.team_id, p.display_name,
  pp.permission_id, pm.identifier, pm.config
  FROM policies p LEFT JOIN policy_permissions pp ON pp.policy_id = p.id
  LEFT JOIN permissions pm ON pm.id = pp.permission_id
  WHERE p.id = $1 AND p.slug = $2 ORDER BY pp.id`;
const userQuery = `SELECT u.pubkey, u.tenant_id, u.email_verification_token, u.email_verified,
  EXISTS(SELECT 1 FROM personal_keys pk WHERE pk.user_pubkey = u.pubkey
    AND pk.tenant_id = u.tenant_id AND octet_length(pk.encrypted_secret_key) > 32) AS has_encrypted_key
  FROM users u JOIN tenants t ON t.id = u.tenant_id
  WHERE u.email = $1 AND t.domain = $2`;

export function createFixtureHelpers(io: FixtureIO) {
  const policies = new WeakMap<PolicyFixture, { config: FixtureConfig; permissions: PermissionRow[]; mutating: boolean }>();
  const sessions = new WeakMap<SessionFixture, FixtureConfig>();

  async function checkManifest(c: FixtureConfig): Promise<void> {
    validConfig(c);
    let raw: unknown;
    try { raw = await io.readOwnership(); } catch { throw new Error("challenge_image:ownership_manifest"); }
    const expected = {
      schema_version: 1, nonce: c.nonce, source_sha: c.sourceSha, daemon_image_id: c.daemonImageId,
      namespace_owner_id: c.namespaceOwnerId, client_id: c.clientId,
      database_url: DATABASE_URL, base_url: BASE_URL, relay_url: RELAY_URL,
    };
    requireFixture(raw && typeof raw === "object" && !Array.isArray(raw), "ownership_manifest");
    const m = raw as Record<string, unknown>;
    requireFixture(Object.keys(m).length === Object.keys(expected).length && Object.entries(expected).every(([k, v]) => m[k] === v), "ownership_manifest");
  }
  async function ownedDb<T>(c: FixtureConfig, operation: (db: Database) => Promise<T>): Promise<T> {
    await checkManifest(c);
    try {
      return await io.withDb(async db => {
        const result = await db.query("SELECT current_database() AS database");
        requireFixture(result.rows.length === 1 && result.rows[0].database === "keycast_image_acceptance", "database_identity");
        return operation(db);
      });
    } catch (error) {
      // Never let pg connection errors or row contents become test diagnostics.
      if (error instanceof Error && /^challenge_image:[a-z_]+$/.test(error.message)) throw error;
      throw new Error("challenge_image:database_operation");
    }
  }
  async function assertOwnedFixture(c: FixtureConfig): Promise<void> { await ownedDb(c, async () => {}); }
  async function transaction<T>(db: Database, operation: () => Promise<T>): Promise<T> {
    await db.query("BEGIN");
    try { const result = await operation(); await db.query("COMMIT"); return result; }
    catch (error) { await db.query("ROLLBACK"); throw error; }
  }
  async function assertPolicy(db: Database, p: PolicyFixture): Promise<void> {
    const owner = policies.get(p);
    requireFixture(owner && p.scope === `policy:${p.slug}` && p.slug !== "challenges", "policy_ownership");
    const { rows } = await db.query(policyQuery, [p.id, p.slug]);
    requireFixture(rows.length > 0 && rows.every(r => r.policy_id === p.id && r.slug === p.slug && r.team_id === null && r.display_name === p.displayName), "policy_binding");
    const actual = rows.filter(r => r.permission_id !== null);
    requireFixture(actual.length === owner.permissions.length && actual.every((r, i) => r.permission_id === owner.permissions[i].id
      && r.identifier === owner.permissions[i].identifier && r.config === owner.permissions[i].config), "policy_permissions");
  }
  async function preparePolicies(c: FixtureConfig): Promise<PolicyFixtures> {
    return ownedDb(c, async db => transaction(db, async () => {
      const prepared = {} as PolicyFixtures;
      for (const kind of ["restricted", "empty", "intersection"] as const) {
        const slug = `ci-${randomBytes(16).toString("hex")}-${kind}`;
        const displayName = `Synthetic acceptance ${kind}`;
        const inserted = await db.query(`INSERT INTO policies (slug, display_name, name, description, team_id)
          VALUES ($1, $2, $3, $4, NULL) RETURNING id`, [slug, displayName, displayName, "Synthetic acceptance"]);
        requireFixture(inserted.rows.length === 1 && Number.isSafeInteger(inserted.rows[0].id), "policy_insert");
        const p: PolicyFixture = Object.freeze({ id: inserted.rows[0].id, slug, scope: `policy:${slug}`, displayName, kind });
        const permissions: PermissionRow[] = [];
        for (const [identifier, config] of permissionSpecs[kind]) {
          const permission = await db.query("INSERT INTO permissions (identifier, config) VALUES ($1, $2) RETURNING id", [identifier, config]);
          requireFixture(permission.rows.length === 1 && Number.isSafeInteger(permission.rows[0].id), "permission_insert");
          const id = permission.rows[0].id;
          await db.query("INSERT INTO policy_permissions (policy_id, permission_id) VALUES ($1, $2)", [p.id, id]);
          permissions.push({ id, identifier, config });
        }
        policies.set(p, { config: Object.freeze({ ...c }), permissions, mutating: false });
        await assertPolicy(db, p);
        prepared[kind] = p;
      }
      return prepared;
    }));
  }
  async function jsonRequest(request: APIRequestContext, method: "get" | "post", route: string, data?: unknown, cookie?: string) {
    try {
      const response = await request[method](BASE_URL + route, {
        data, headers: { Origin: BASE_URL, ...(cookie ? { Cookie: cookie } : {}) },
        timeout: API_TIMEOUT, maxRedirects: 0,
      });
      requireFixture(response.ok(), "http_status");
      const body = await response.json();
      requireFixture(body && typeof body === "object" && !Array.isArray(body), "http_json");
      return { body, headers: response.headers() };
    } catch (error) {
      if (error instanceof Error && /^challenge_image:[a-z_]+$/.test(error.message)) throw error;
      // Playwright exceptions can contain complete request/response secrets.
      throw new Error("challenge_image:http_request");
    }
  }
  async function registerSyntheticUser(request: APIRequestContext, c: FixtureConfig): Promise<SessionFixture> {
    await assertOwnedFixture(c);
    const email = `image-${c.nonce}${randomBytes(8).toString("hex")}@example.test`;
    const { body: registered } = await jsonRequest(request, "post", "/api/auth/register", { email, password: randomBytes(32).toString("base64url") });
    requireFixture(registered.success === true && registered.verification_required === true && HEX64.test(registered.pubkey), "registration");
    let token: string | undefined;
    let tenantId: number | undefined;
    for (let attempt = 0; attempt < 10; attempt++) {
      const user = await ownedDb(c, async db => (await db.query(userQuery, [email, "localhost"])).rows);
      requireFixture(user.length <= 1, "registration_binding");
      if (user.length === 1) {
        requireFixture(user[0].pubkey === registered.pubkey && Number.isSafeInteger(Number(user[0].tenant_id)) && user[0].has_encrypted_key === true, "registration_binding");
        token = user[0].email_verification_token; tenantId = Number(user[0].tenant_id);
        if (typeof token === "string" && token.length > 0) break;
      }
      await io.pause(300);
    }
    requireFixture(token && tenantId, "verification_token_timeout");
    let cookie: string | undefined;
    for (let attempt = 0; attempt < 10; attempt++) {
      await assertOwnedFixture(c);
      const verified = await jsonRequest(request, "post", "/api/auth/verify-email", { token });
      if (verified.body.status === "processing") { await io.pause(500); continue; }
      requireFixture(verified.body.success === true && verified.body.authenticated === true, "verification");
      cookie = verified.headers["set-cookie"]?.match(/(?:^|,\s*)keycast_session=([^;\s,]+)/)?.[1];
      requireFixture(cookie, "session_cookie");
      break;
    }
    requireFixture(cookie, "verification_timeout");
    // Minimal team fixture, following TeamRepository::create_with_admin. No
    // global admin, user/key insertion, default policy, or allowlist change.
    const teamId = await ownedDb(c, async db => transaction(db, async () => {
      const user = (await db.query(userQuery, [email, "localhost"])).rows;
      requireFixture(user.length === 1 && user[0].pubkey === registered.pubkey && Number(user[0].tenant_id) === tenantId
        && user[0].email_verified === true && user[0].has_encrypted_key === true, "verified_user_binding");
      const team = await db.query("INSERT INTO teams (tenant_id, name) VALUES ($1, $2) RETURNING id", [tenantId, `Synthetic acceptance ${randomBytes(12).toString("hex")}`]);
      requireFixture(team.rows.length === 1 && Number.isSafeInteger(team.rows[0].id), "team_insert");
      await db.query("INSERT INTO team_users (team_id, user_pubkey, role) VALUES ($1, $2, 'admin') RETURNING id", [team.rows[0].id, registered.pubkey]);
      return team.rows[0].id as number;
    }));
    const session = Object.freeze({ cookie: `keycast_session=${cookie}`, pubkey: registered.pubkey as string, tenantId, teamId });
    sessions.set(session, Object.freeze({ ...c }));
    return session;
  }
  async function issueGrant(request: APIRequestContext, session: SessionFixture, policy: PolicyFixture): Promise<Grant> {
    const owner = policies.get(policy), sessionConfig = sessions.get(session);
    requireFixture(owner && sessionConfig && policy.scope === `policy:${policy.slug}`
      && JSON.stringify(sessionConfig) === JSON.stringify(owner.config), "grant_ownership");
    await ownedDb(owner.config, db => assertPolicy(db, policy));
    const pkce = generatePKCE();
    const clientId = `image-${randomBytes(16).toString("hex")}`;
    const redirectUri = BASE_URL + "/acceptance-callback";
    const { body: auth } = await jsonRequest(request, "post", "/api/oauth/authorize", {
      client_id: clientId, redirect_uri: redirectUri, scope: policy.scope, approved: true,
      code_challenge: pkce.challenge, code_challenge_method: pkce.method,
    }, session.cookie);
    requireFixture(typeof auth.code === "string" && auth.code.length > 0, "authorization_code");
    await assertOwnedFixture(owner.config);
    const { body: token } = await jsonRequest(request, "post", "/api/oauth/token", {
      grant_type: "authorization_code", code: auth.code, client_id: clientId,
      redirect_uri: redirectUri, code_verifier: pkce.verifier,
    });
    requireFixture(token.scope === policy.scope && token.scope !== "policy:full", "grant_scope");
    requireFixture(token.policy?.slug === policy.slug && token.policy.display_name === policy.displayName
      && typeof token.policy.description === "string" && Array.isArray(token.policy.permissions)
      && token.policy.permissions.length === owner.permissions.length
      && token.policy.permissions.every((p: any) => typeof p.title === "string" && p.title.length > 0 && typeof p.description === "string" && p.description.length > 0), "grant_display");
    requireFixture(typeof token.access_token === "string" && token.access_token.length > 0
      && typeof token.refresh_token === "string" && token.refresh_token.length > 0 && token.token_type === "Bearer"
      && typeof token.authorization_handle === "string" && HEX64.test(token.authorization_handle), "grant_token");
    let bunker: URL;
    try { bunker = new URL(token.bunker_url); } catch { throw new Error("challenge_image:grant_bunker"); }
    const relays = bunker.searchParams.getAll("relay");
    requireFixture(bunker.protocol === "bunker:" && HEX64.test(bunker.hostname) && !bunker.username && !bunker.password
      && !bunker.port && !bunker.hash && !bunker.pathname && relays.length === 1 && relays[0] === RELAY_URL
      && bunker.searchParams.getAll("secret").length === 1 && bunker.searchParams.get("secret"), "grant_relay");
    const authorizationId = await ownedDb(owner.config, async db => {
      await assertPolicy(db, policy);
      const { rows } = await db.query(`SELECT id, policy_id, user_pubkey, tenant_id, bunker_public_key
        FROM oauth_authorizations WHERE authorization_handle = $1 AND user_pubkey = $2
        AND tenant_id = $3 AND client_id = $4 AND revoked_at IS NULL`, [token.authorization_handle, session.pubkey, session.tenantId, clientId]);
      requireFixture(rows.length === 1 && Number.isSafeInteger(rows[0].id) && rows[0].policy_id === policy.id
        && rows[0].user_pubkey === session.pubkey && Number(rows[0].tenant_id) === session.tenantId
        && rows[0].bunker_public_key === bunker.hostname, "grant_database_binding");
      // oauth_authorizations.relays is currently unused at runtime. Do not
      // replace it or connect to it; response/signer use BUNKER_RELAYS.
      return rows[0].id as number;
    });
    return { accessToken: token.access_token, refreshToken: token.refresh_token, bunkerUrl: token.bunker_url,
      scope: token.scope, pubkey: session.pubkey, authorizationId };
  }
  async function withPermissionMutation(policy: PolicyFixture, identifier: string, configText: string, operation: () => Promise<void>): Promise<void> {
    const owner = policies.get(policy);
    requireFixture(owner && !owner.mutating && owner.permissions.length > 0 && typeof identifier === "string" && typeof configText === "string", "mutation_ownership");
    const row = owner.permissions[0];
    const update = (db: Database, id: string, text: string) => db.query(`UPDATE permissions SET identifier = $1, config = $2, updated_at = NOW()
      WHERE id = $3 AND EXISTS(SELECT 1 FROM policy_permissions pp WHERE pp.permission_id = permissions.id AND pp.policy_id = $4)
      RETURNING id`, [id, text, row.id, policy.id]);
    await ownedDb(owner.config, db => assertPolicy(db, policy));
    owner.mutating = true;
    try {
      await ownedDb(owner.config, async db => {
        requireFixture((await update(db, identifier, configText)).rowCount === 1, "mutation_row");
      });
      await operation();
    }
    finally {
      try { await ownedDb(owner.config, async db => { requireFixture((await update(db, row.identifier, row.config)).rowCount === 1, "mutation_restore"); }); }
      finally { owner.mutating = false; }
    }
  }
  return { assertOwnedFixture, preparePolicies, registerSyntheticUser, issueGrant, withPermissionMutation };
}

const helpers = createFixtureHelpers({
  async readOwnership() {
    const file = await open(OWNERSHIP_PATH, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await file.stat();
      requireFixture(stat.isFile() && (stat.mode & 0o777) === 0o600 && stat.size <= 4096, "ownership_file");
      return JSON.parse(await file.readFile("utf8"));
    } finally { await file.close(); }
  },
  async withDb(operation) {
    const client = new Client({ connectionString: DATABASE_URL, connectionTimeoutMillis: API_TIMEOUT, query_timeout: API_TIMEOUT, statement_timeout: API_TIMEOUT });
    try { await client.connect(); return await operation(client); }
    finally { await client.end(); }
  },
  pause: milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
});
export const { assertOwnedFixture, preparePolicies, registerSyntheticUser, issueGrant, withPermissionMutation } = helpers;
