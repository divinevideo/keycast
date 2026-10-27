import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import path from "node:path";
import defaultConfig from "../playwright.config";
import dedicatedConfig from "../challenge-image.config";
import { assertDiscoverySeparation, configFromEnvironment, createFixtureHelpers, type FixtureConfig } from "./challenge-image-fixtures";

const manifest = {
  schema_version: 1, nonce: "a".repeat(32), source_sha: "b".repeat(40),
  daemon_image_id: `sha256:${"c".repeat(64)}`, namespace_owner_id: "d".repeat(64), client_id: "e".repeat(64),
  database_url: "postgres://postgres:acceptance@localhost:5432/keycast_image_acceptance",
  base_url: "http://localhost:3000", relay_url: "ws://localhost:8080",
};
const environment = {
  CHALLENGE_IMAGE_NONCE: manifest.nonce, CHALLENGE_IMAGE_SOURCE_SHA: manifest.source_sha,
  CHALLENGE_IMAGE_DAEMON_IMAGE_ID: manifest.daemon_image_id, CHALLENGE_IMAGE_NAMESPACE_OWNER_ID: manifest.namespace_owner_id,
  CHALLENGE_IMAGE_CLIENT_ID: manifest.client_id, BUNKER_RELAYS: manifest.relay_url,
};
const config = (): FixtureConfig => configFromEnvironment(environment);
const publicKey = "f".repeat(64); // Synthetic public identifier only.

// Only external boundaries are replaced. Real helper control flow, SQL
// parameters and request bodies remain under test; no services run.
function fixture(options: { ownership?: unknown; database?: string; token?: any; user?: any; authorization?: any; missingToken?: boolean; processing?: boolean; httpError?: boolean; mutationFailure?: boolean } = {}) {
  const queries: { sql: string; values: any[] }[] = [];
  const calls: { method: string; url: string; options: any }[] = [];
  const policies: any[] = [], permissions: any[] = [], links: any[] = [];
  let grantPolicy: any, readFails = false, failedMutation = false, verifiedCalls = 0;
  const db = { async query(sql: string, values: any[] = []) {
    queries.push({ sql, values });
    const q = sql.replace(/\s+/g, " ").trim();
    if (/^(INSERT|UPDATE|DELETE)/.test(q)) expect(values.length).toBeGreaterThan(0);
    expect(q).not.toMatch(/TRUNCATE|DELETE FROM/);
    let rows: any[];
    if (q === "SELECT current_database() AS database") rows = [{ database: options.database ?? "keycast_image_acceptance" }];
    else if (q.startsWith("INSERT INTO policies")) {
      const row = { id: policies.length + 1, slug: values[0], display_name: values[1], team_id: null };
      policies.push(row); rows = [row];
    } else if (q.startsWith("INSERT INTO permissions")) {
      const row = { id: permissions.length + 11, identifier: values[0], config: values[1] };
      permissions.push(row); rows = [row];
    } else if (q.startsWith("INSERT INTO policy_permissions")) { links.push({ policy_id: values[0], permission_id: values[1] }); rows = []; }
    else if (q.includes("FROM policies p LEFT JOIN policy_permissions")) {
      const p = policies.find(p => p.id === values[0] && p.slug === values[1]);
      rows = !p ? [] : links.filter(l => l.policy_id === p.id).map(l => ({ ...p, ...permissions.find(r => r.id === l.permission_id), policy_id: p.id, permission_id: l.permission_id }));
      if (p && !rows.length) rows = [{ ...p, policy_id: p.id, permission_id: null, identifier: null, config: null }];
    } else if (q.includes("FROM users u JOIN tenants")) rows = [{ pubkey: publicKey, tenant_id: 7, email_verification_token: "synthetic-verification-token", email_verified: true, has_encrypted_key: true, ...options.user, ...(options.missingToken ? { email_verification_token: null } : {}) }];
    else if (q.startsWith("INSERT INTO teams")) rows = [{ id: 21 }];
    else if (q.startsWith("INSERT INTO team_users")) rows = [{ id: 31 }];
    else if (q.includes("FROM oauth_authorizations")) rows = [{ id: 41, policy_id: grantPolicy.id, user_pubkey: publicKey, tenant_id: 7, bunker_public_key: "1".repeat(64), ...options.authorization }];
    else if (q.startsWith("UPDATE permissions")) {
      const row = permissions.find(p => p.id === values[2]);
      if (!row || !links.some(l => l.permission_id === row.id && l.policy_id === values[3])) throw new Error("foreign mutation");
      row.identifier = values[0]; row.config = values[1];
      if (options.mutationFailure && !failedMutation) { failedMutation = true; throw new Error("private connection failure after write"); }
      rows = [{ id: row.id }];
    } else if (["BEGIN", "COMMIT", "ROLLBACK"].includes(q)) rows = [];
    else throw new Error("unexpected query boundary");
    return { rows, rowCount: rows.length || (q.startsWith("INSERT INTO policy_permissions") ? 1 : 0) };
  } };
  const helpers = createFixtureHelpers({ readOwnership: async () => {
    if (readFails) throw new Error("private filesystem details"); return options.ownership === undefined ? manifest : options.ownership;
  }, withDb: async (fn: any) => fn(db), pause: async () => {} });
  const request = Object.fromEntries(["get", "post"].map(method => [method, async (url: string, opts: any) => {
    calls.push({ method, url, options: opts });
    if (options.httpError) throw new Error("PRIVATE token and cookie diagnostics");
    expect(url.startsWith("http://localhost:3000/api/")).toBe(true); expect(opts.timeout).toBe(15000); expect(opts.maxRedirects).toBe(0);
    let body: any = {};
    if (url.endsWith("/register")) body = { success: true, pubkey: publicKey, verification_required: true };
    else if (url.endsWith("/verify-email")) body = options.processing && verifiedCalls++ === 0 ? { success: false, status: "processing", retry_after: 1 } : { success: true, authenticated: true };
    else if (url.endsWith("/authorize")) body = { code: "synthetic-code", redirect_uri: opts.data.redirect_uri };
    else if (url.endsWith("/token")) body = {
      access_token: "synthetic-access", refresh_token: "synthetic-refresh", token_type: "Bearer", expires_in: 3600,
      authorization_handle: "2".repeat(64), scope: `policy:${grantPolicy.slug}`,
      bunker_url: `bunker://${"1".repeat(64)}?relay=ws%3A%2F%2Flocalhost%3A8080&secret=synthetic-secret`,
      policy: { slug: grantPolicy.slug, display_name: grantPolicy.displayName, description: "Synthetic acceptance", permissions: grantPolicy.kind === "empty" ? [] : [...[{ icon: "🏆", title: "Challenges and contest curation", description: "Synthetic display" }], ...(grantPolicy.kind === "intersection" ? [{ icon: "🔒", title: "Other actions", description: "Synthetic restriction" }] : [])] }, ...options.token,
    }; else throw new Error("unexpected HTTP boundary");
    return { ok: () => true, status: () => 200, json: async () => body, headers: () => ({ "set-cookie": "keycast_session=synthetic-session; Path=/; HttpOnly" }) };
  }]));
  return { ...helpers, queries, calls, policies, permissions, links, request: request as any,
    missingManifest() { readFails = true; }, bind(p: any) { grantPolicy = p; } };
}
const writes = (f: ReturnType<typeof fixture>) => f.queries.filter(q => /^\s*(INSERT|UPDATE|DELETE|TRUNCATE)/.test(q.sql));

// Task 3 must run the real --list regression once its real spec exists.
// Here the contract rejects overlapping roots, default inclusion or no suite.
test("default_discovery_excludes_challenge_image_suite", () => {
  const root = path.resolve(import.meta.dir, "..");
  const roots = { defaultTestDir: path.resolve(root, defaultConfig.testDir!), dedicatedTestDir: path.resolve(root, dedicatedConfig.testDir!) };
  expect(() => assertDiscoverySeparation({ ...roots, defaultListing: "tests/oauth.spec.ts:1:1 › OAuth", dedicatedListing: "challenge-image/challenge-image.spec.ts:1:1 › image" })).not.toThrow();
  expect(() => assertDiscoverySeparation({ ...roots, defaultListing: "challenge-image.spec.ts", dedicatedListing: "challenge-image.spec.ts" })).toThrow();
  expect(() => assertDiscoverySeparation({ ...roots, dedicatedTestDir: roots.defaultTestDir, defaultListing: "", dedicatedListing: "challenge-image.spec.ts" })).toThrow();
  expect(() => assertDiscoverySeparation({ ...roots, defaultListing: "", dedicatedListing: "Total: 0 tests" })).toThrow();
});

describe("ownership guards", () => {
  test("requires every runner identity and exact effective relay", () => {
    for (const key of Object.keys(environment)) { const env: any = { ...environment }; delete env[key]; expect(() => configFromEnvironment(env)).toThrow(); }
    expect(() => configFromEnvironment({ ...environment, BUNKER_RELAYS: "wss://relay.example.test" })).toThrow();
  });
  test("matching manifest checks current database before proceeding", async () => {
    const f = fixture(); await f.assertOwnedFixture(config()); expect(f.queries.map(q => q.sql)).toEqual(["SELECT current_database() AS database"]);
  });
  for (const [name, ownership] of Object.entries({ absent: null, foreign: { ...manifest, nonce: "0".repeat(32) }, extra: { ...manifest, extra: true },
    wrongSchema: { ...manifest, schema_version: "1" }, wrongImage: { ...manifest, daemon_image_id: `sha256:${"0".repeat(64)}` },
    remote: { ...manifest, base_url: "https://example.test" }, relay: { ...manifest, relay_url: "wss://example.test" }, database: { ...manifest, database_url: "postgres://example.test/keycast" },
  })) test(`${name} ownership fails before SQL writes or HTTP`, async () => {
    const f = fixture({ ownership }); await expect(f.preparePolicies(config())).rejects.toThrow("ownership");
    await expect(f.registerSyntheticUser(f.request, config())).rejects.toThrow("ownership"); expect(f.queries).toHaveLength(0); expect(f.calls).toHaveLength(0);
  });
  test("missing manifest and wrong current database fail closed", async () => {
    const missing = fixture(); missing.missingManifest(); await expect(missing.preparePolicies(config())).rejects.toThrow("ownership"); expect(missing.queries).toHaveLength(0);
    const foreign = fixture({ database: "keycast" }); await expect(foreign.preparePolicies(config())).rejects.toThrow("database");
    await expect(foreign.registerSyntheticUser(foreign.request, config())).rejects.toThrow("database"); expect(writes(foreign)).toHaveLength(0); expect(foreign.calls).toHaveLength(0);
  });
  test("non-loopback caller config fails before database or HTTP", async () => {
    for (const field of ["baseUrl", "relayUrl", "databaseUrl", "bunkerRelays"] as const) {
      const f = fixture(); const c = { ...config(), [field]: "https://example.test" }; await expect(f.preparePolicies(c)).rejects.toThrow();
      await expect(f.registerSyntheticUser(f.request, c)).rejects.toThrow(); expect(f.queries).toHaveLength(0); expect(f.calls).toHaveLength(0);
    }
  });
});

test("fresh restricted/empty/AND policies own exact TEXT permission links", async () => {
  const f = fixture(); const p = await f.preparePolicies(config()); const second = await f.preparePolicies(config());
  expect(new Set(f.policies.map(p => p.slug)).size).toBe(6); expect(f.policies.every(p => p.team_id === null && p.slug !== "challenges" && p.slug.length <= 50)).toBe(true);
  expect(p.restricted.scope).toBe(`policy:${p.restricted.slug}`); expect(p.restricted.slug).not.toBe(second.restricted.slug);
  for (const [policy, expected] of [[p.restricted, [["challenge_actions", "{}"]]], [p.empty, []], [p.intersection, [["challenge_actions", "{}"], ["allowed_kinds", '{"allowed_kinds":[31923]}']]]] as const) {
    expect(f.links.filter(l => l.policy_id === policy.id).map(l => { const r = f.permissions.find(r => r.id === l.permission_id); return [r.identifier, r.config]; })).toEqual(expected);
  }
});

test("normal registration verifies generated image key and creates only team admin", async () => {
  const f = fixture(); const s = await f.registerSyntheticUser(f.request, config()); expect(s.pubkey).toBe(publicKey); expect(s.cookie).toBe("keycast_session=synthetic-session"); expect(s.teamId).toBe(21);
  const data = f.calls.find(c => c.url.endsWith("/register"))!.options.data; expect(data.email).toMatch(/^image-[a-f0-9]+@example\.test$/); expect(data.password.length).toBeGreaterThanOrEqual(32); expect(Object.keys(data).sort()).toEqual(["email", "password"]);
  expect(f.queries.filter(q => q.sql.includes("FROM users u JOIN tenants")).every(q => q.values[0] === data.email && q.values[1] === "localhost")).toBe(true);
  expect(f.calls.find(c => c.url.endsWith("/verify-email"))!.options.data).toEqual({ token: "synthetic-verification-token" });
  expect(writes(f).map(q => q.sql.match(/INSERT INTO (\w+)/)![1])).toEqual(["teams", "team_users"]); expect(writes(f)[1].values).toEqual([21, publicKey]);
});

test("PKCE explicit policy and owned relay plus database binding yield memory-only grant", async () => {
  const f = fixture(); const p = await f.preparePolicies(config()); const s = await f.registerSyntheticUser(f.request, config()); f.bind(p.restricted); const g = await f.issueGrant(f.request, s, p.restricted);
  expect(g).toEqual({ accessToken: "synthetic-access", refreshToken: "synthetic-refresh", bunkerUrl: `bunker://${"1".repeat(64)}?relay=ws%3A%2F%2Flocalhost%3A8080&secret=synthetic-secret`, scope: `policy:${p.restricted.slug}`, pubkey: publicKey, authorizationId: 41 });
  const auth = f.calls.find(c => c.url.endsWith("/authorize"))!.options, token = f.calls.find(c => c.url.endsWith("/token"))!.options;
  expect(auth.data.scope).toBe(p.restricted.scope); expect(auth.headers.Cookie).toBe(s.cookie); expect(auth.data.code_challenge_method).toBe("S256");
  expect(createHash("sha256").update(token.data.code_verifier).digest("base64url")).toBe(auth.data.code_challenge); expect(token.data.client_id).toBe(auth.data.client_id); expect(token.data.redirect_uri).toBe(auth.data.redirect_uri);
});
for (const [name, token] of Object.entries({ full: { scope: "policy:full" }, absentScope: { scope: undefined }, absentDisplay: { policy: undefined },
  remoteRelay: { bunker_url: `bunker://${"1".repeat(64)}?relay=wss%3A%2F%2Fexample.test&secret=synthetic` }, extraRelay: { bunker_url: `bunker://${"1".repeat(64)}?relay=ws%3A%2F%2Flocalhost%3A8080&relay=wss%3A%2F%2Fexample.test&secret=synthetic` },
})) test(`rejects ${name} grant with sanitized diagnostics`, async () => {
  const f = fixture({ token }); const p = await f.preparePolicies(config()); const s = await f.registerSyntheticUser(f.request, config()); f.bind(p.restricted); await expect(f.issueGrant(f.request, s, p.restricted)).rejects.toThrow(/^challenge_image:/);
});
test("absent explicit scope, foreign policy and changed links fail before grant HTTP", async () => {
  const f = fixture(); const p = await f.preparePolicies(config()); const s = await f.registerSyntheticUser(f.request, config()); f.calls.length = 0;
  await expect(f.issueGrant(f.request, s, { ...p.restricted, scope: undefined })).rejects.toThrow(); await expect(f.issueGrant(f.request, s, { ...p.restricted })).rejects.toThrow();
  f.links.push({ policy_id: p.restricted.id, permission_id: f.permissions[1].id }); await expect(f.issueGrant(f.request, s, p.restricted)).rejects.toThrow(); expect(f.calls).toHaveLength(0);
});
test("failed mutation restores only its owned row in finally", async () => {
  const f = fixture(); const p = await f.preparePolicies(config()); const before = structuredClone(f.permissions);
  await expect(f.withPermissionMutation(p.restricted, "unknown_permission", "{", async () => { expect(f.permissions[0].identifier).toBe("unknown_permission"); expect(f.permissions[0].config).toBe("{"); throw new Error("synthetic operation failure"); })).rejects.toThrow("synthetic operation failure");
  expect(f.permissions).toEqual(before); expect(f.queries.filter(q => q.sql.startsWith("UPDATE permissions")).map(q => q.values)).toEqual([["unknown_permission", "{", 11, 1], ["challenge_actions", "{}", 11, 1]]);
  await expect(f.withPermissionMutation({ ...p.restricted }, "unknown_permission", "{}", async () => {})).rejects.toThrow(); expect(f.queries.filter(q => q.sql.startsWith("UPDATE permissions"))).toHaveLength(2);
});


test("empty and AND grants preserve their distinct permission bindings", async () => {
  const f = fixture(); const policies = await f.preparePolicies(config()); const session = await f.registerSyntheticUser(f.request, config());
  for (const policy of [policies.empty, policies.intersection]) {
    f.bind(policy); const grant = await f.issueGrant(f.request, session, policy);
    expect(grant.scope).toBe(policy.scope);
  }
});
for (const [name, authorization] of Object.entries({ wrongPolicy: { policy_id: 900 }, wrongUser: { user_pubkey: "0".repeat(64) }, wrongTenant: { tenant_id: 90 }, wrongBunker: { bunker_public_key: "0".repeat(64) } })) test(`rejects ${name} authorization database binding`, async () => {
  const f = fixture({ authorization }); const policies = await f.preparePolicies(config()); const session = await f.registerSyntheticUser(f.request, config()); f.bind(policies.restricted);
  await expect(f.issueGrant(f.request, session, policies.restricted)).rejects.toThrow("grant_database_binding");
});
test("verification token lookup is bounded and never bypasses verification", async () => {
  const f = fixture({ missingToken: true });
  await expect(f.registerSyntheticUser(f.request, config())).rejects.toThrow("verification_token_timeout");
  expect(f.queries.filter(q => q.sql.includes("FROM users u JOIN tenants"))).toHaveLength(10);
  expect(f.calls).toHaveLength(1); expect(writes(f)).toHaveLength(0);
});
test("verification retries processing and refuses an unencrypted user", async () => {
  const retry = fixture({ processing: true }); await retry.registerSyntheticUser(retry.request, config());
  expect(retry.calls.filter(c => c.url.endsWith("/verify-email"))).toHaveLength(2);
  const invalid = fixture({ user: { has_encrypted_key: false } });
  await expect(invalid.registerSyntheticUser(invalid.request, config())).rejects.toThrow("registration_binding");
  expect(invalid.calls).toHaveLength(1); expect(writes(invalid)).toHaveLength(0);
});
test("HTTP exceptions never reveal request token or cookie diagnostics", async () => {
  const f = fixture({ httpError: true });
  await expect(f.registerSyntheticUser(f.request, config())).rejects.toThrow(/^challenge_image:http_request$/);
});
test("mutation restores after an applied write reports a connection failure", async () => {
  const f = fixture({ mutationFailure: true }); const p = await f.preparePolicies(config()); const before = structuredClone(f.permissions);
  await expect(f.withPermissionMutation(p.restricted, "unknown_permission", "{", async () => {})).rejects.toThrow("database_operation");
  expect(f.permissions).toEqual(before);
});
