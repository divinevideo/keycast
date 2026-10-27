import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import defaultConfig from "../playwright.config";
import dedicatedConfig from "../challenge-image.config";
import { assertClientPackaging, assertDiscoverySeparation, configFromEnvironment, createFixtureHelpers, type FixtureConfig } from "./challenge-image-fixtures";

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

// Synthetic malformed-list cases exercise strict parsing; the real collection
// regression below passes actual stdout and exit status from the Node CLI.
const discoveryRoots = {
  defaultTestDir: path.resolve(import.meta.dir, "../", defaultConfig.testDir!),
  dedicatedTestDir: path.resolve(import.meta.dir, "../", dedicatedConfig.testDir!),
};
const discovery = {
  ...discoveryRoots, defaultExitCode: 0, dedicatedExitCode: 0,
  defaultListing: "Listing tests:\n  [chromium] › oauth.spec.ts:10:3 › OAuth\nTotal: 1 test in 1 file\n",
  dedicatedListing: "Listing tests:\n  [chromium] › challenge-image.spec.ts:12:3 › image\nTotal: 1 test in 1 file\n",
};
test("default_discovery_excludes_challenge_image_suite", () => {
  expect(() => assertDiscoverySeparation(discovery)).not.toThrow();
  expect(() => assertDiscoverySeparation({ ...discovery, defaultListing: discovery.dedicatedListing })).toThrow();
  expect(() => assertDiscoverySeparation({ ...discovery, dedicatedTestDir: discovery.defaultTestDir })).toThrow();
  expect(() => assertDiscoverySeparation({ ...discovery, dedicatedListing: "Listing tests:\nTotal: 0 tests in 0 files\n" })).toThrow();
});
test("discovery accepts the observed project-free Node collection format", () => {
  expect(() => assertDiscoverySeparation({ ...discovery,
    dedicatedListing: "Listing tests:\n  challenge-image.spec.ts:1:83 › collection probe\nTotal: 1 test in 1 file\n",
  })).not.toThrow();
});
for (const [name, change] of Object.entries({
  failedDefault: { defaultExitCode: 1 }, failedDedicated: { dedicatedExitCode: 1 },
  interruptedDedicated: { dedicatedExitCode: null },
  throwingImport: { dedicatedExitCode: 1, dedicatedListing: "Listing tests:\nTotal: 0 tests in 0 files\nError: synthetic collection import failure\n  at challenge-image.spec.ts:1:7\n" },
  filenameInDiagnostic: { dedicatedListing: "Listing tests:\nTotal: 0 tests in 0 files\nError: challenge-image.spec.ts:1:7\n" },
  missingRow: { dedicatedListing: "Listing tests:\nTotal: 1 test in 1 file\nError: challenge-image.spec.ts:1:7\n" },
  missingTotal: { dedicatedListing: "Listing tests:\n  [chromium] › challenge-image.spec.ts:12:3 › image\n" },
  mismatchedCount: { dedicatedListing: "Listing tests:\n  [chromium] › challenge-image.spec.ts:12:3 › image\nTotal: 2 tests in 1 file\n" },
})) test(`discovery rejects ${name} collection`, () => {
  expect(() => assertDiscoverySeparation({ ...discovery, ...change })).toThrow();
});

// Bun resolves the real relative-import graph without executing module code.
// The fixture JSON is runtime-read and must be included explicitly as an asset.
function clientLocalGraph(entrypoints: string[]): string[] {
  const scratch = mkdtempSync(path.join(tmpdir(), "keycast-image-packaging-"));
  try {
    const graph = path.join(scratch, "graph.json");
    const built = spawnSync(process.execPath, ["build", ...entrypoints, "--target=node", "--packages=external",
      `--outdir=${scratch}`, `--metafile=${graph}`], { cwd: path.resolve(import.meta.dir, ".."), timeout: 15000, encoding: "utf8" });
    expect(built.status).toBe(0);
    return Object.keys(JSON.parse(readFileSync(graph, "utf8")).inputs).map(file => path.posix.normalize(`e2e/${file}`));
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
test("client packaging covers the actual current helper graph with precise copies", () => {
  const dockerfile = readFileSync(path.resolve(import.meta.dir, "../Dockerfile.acceptance"), "utf8");
  const requiredPaths = [...clientLocalGraph(["challenge-image/challenge-image.spec.ts", "challenge-image.config.ts"]), "core/tests/fixtures/challenges/v1/events.json"];
  expect(requiredPaths).toContain("e2e/challenge-image/challenge-image.spec.ts");
  expect(requiredPaths).toContain("e2e/challenge-image.config.ts");
  expect(requiredPaths).toContain("e2e/helpers/challenge-image-rpc.ts");
  expect(readFileSync(path.resolve(import.meta.dir, "../../core/tests/fixtures/challenges/v1/events.json"), "utf8").length).toBeGreaterThan(0);
  expect(requiredPaths).toContain("e2e/helpers/challenge-image-fixtures.ts");
  expect(requiredPaths).toContain("e2e/helpers/oauth.ts");
  expect(() => assertClientPackaging({ dockerfile, requiredPaths })).not.toThrow();
  // Removing a required transitive module's COPY must fail, even while its
  // source exists in this checkout and the standalone bundle succeeds.
  expect(() => assertClientPackaging({ dockerfile: dockerfile.replace(" e2e/helpers/oauth.ts", ""), requiredPaths })).toThrow();
  expect(() => assertClientPackaging({ dockerfile: dockerfile.replace("./helpers/", "./misplaced/"), requiredPaths })).toThrow();
});
test("client packaging requires exact runtime assets and every real helper", () => {
  const dockerfile = readFileSync(path.resolve(import.meta.dir, "../Dockerfile.acceptance"), "utf8");
  const requiredPaths = [...clientLocalGraph(["challenge-image/challenge-image.spec.ts", "challenge-image.config.ts"]), "core/tests/fixtures/challenges/v1/events.json"];
  expect(() => assertClientPackaging({ dockerfile, requiredPaths })).not.toThrow();
  expect(() => assertClientPackaging({ dockerfile: dockerfile.replace(" e2e/helpers/challenge-image-rpc.ts", ""), requiredPaths })).toThrow();
  expect(() => assertClientPackaging({ dockerfile: dockerfile.replace("COPY core/tests/fixtures/challenges/v1/events.json /core/tests/fixtures/challenges/v1/events.json", ""), requiredPaths })).toThrow();
  expect(() => assertClientPackaging({ dockerfile: dockerfile.replace("/core/tests/fixtures/challenges/v1/events.json", "/wrong/events.json"), requiredPaths })).toThrow();
  expect(() => assertClientPackaging({ dockerfile: dockerfile + "\nCOPY e2e/helpers/ ./helpers/\n", requiredPaths })).toThrow();
  expect(() => assertClientPackaging({ dockerfile: dockerfile + "\nCOPY e2e/helpers/db.ts ./helpers/\n", requiredPaths })).toThrow();
});
const signingCaseNames = [
  "get_public_key", "definition", "entry", "withdraw", "result", "contest_include", "contest_exclude",
  "denied_kind_0", "denied_kind_1", "denied_kind_4", "denied_kind_21", "denied_kind_22", "denied_kind_44", "denied_kind_1059", "denied_kind_22242", "denied_kind_27235", "denied_kind_34235", "denied_kind_34236",
  "unmarked_31923", "unmarked_1111", "unmarked_1985", "mismatched_contest_namespace", "bad_embedded_snapshot",
  "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt", "sign_canonical", "nip17_wrap_batch", "nip17_unwrap_batch", "empty_policy_control", "and_policy_control",
];
const expectedSigningIds = ["http", "nip46"].flatMap(t => signingCaseNames.map(c => `signing.${t}.${c}`));
test("real Node collection isolates and requires every transport matrix row exactly once", () => {
  const cwd = path.resolve(import.meta.dir, "..");
  const list = (config: string) => spawnSync("node", ["node_modules/@playwright/test/cli.js", "test", "--list", "--config", config], {
    cwd, encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024,
    env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
  });
  const normal = list("playwright.config.ts"), dedicated = list("challenge-image.config.ts");
  expect(normal.error).toBeUndefined(); expect(dedicated.error).toBeUndefined();
  assertDiscoverySeparation({ ...discoveryRoots, defaultExitCode: normal.status, dedicatedExitCode: dedicated.status, defaultListing: normal.stdout, dedicatedListing: dedicated.stdout });
  const rows = dedicated.stdout.split(/\r?\n/).flatMap(line => {
    const row = line.match(/^\s+(?:\[[^\]\r\n]+\] › )?challenge-image\.spec\.ts:[1-9]\d*:[1-9]\d* › (signing\.\S+)$/);
    return row ? [row[1]] : [];
  });
  expect(rows.sort()).toEqual([...expectedSigningIds].sort()); expect(new Set(rows).size).toBe(64);
  const runner = spawnSync("python3", ["-B", "-c", "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('acceptance', '../scripts/challenge-image-acceptance.py'); m=importlib.util.module_from_spec(s); sys.modules[s.name]=m; s.loader.exec_module(m); print(json.dumps(m.SUITE_CASE_IDS))"], { cwd, encoding: "utf8", timeout: 15000 });
  expect(runner.status).toBe(0);
  const required: string[] = JSON.parse(runner.stdout);
  expect(required.filter(id => id.startsWith("signing.")).sort()).toEqual([...expectedSigningIds].sort());
  expect(required.filter(id => !id.startsWith("signing.")).sort()).toEqual(["consent.authorize", "consent.refresh", "management.creation-held"]);
}, 60000);

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

test("policy INSERT binds varchar display and text name to separate parameters", async () => {
  const f = fixture(); await f.preparePolicies(config());
  const inserts = f.queries.filter(q => q.sql.startsWith("INSERT INTO policies"));
  expect(inserts).toHaveLength(3);
  for (const [index, query] of inserts.entries()) {
    // PostgreSQL infers VARCHAR(100) for display_name and TEXT for name.
    // This focused assertion protects this one characterized statement.
    expect(query.sql.replace(/\s+/g, " ")).toContain("VALUES ($1, $2, $3, $4, NULL)");
    expect(query.values).toEqual([f.policies[index].slug, f.policies[index].display_name, f.policies[index].display_name, "Synthetic acceptance"]);
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

// Real SDK + synthetic signing/encryption; only network boundaries are replaced.
async function rpcModule() {
  const module = await import("./challenge-image-rpc").catch(() => null);
  expect(module).not.toBeNull(); return module!;
}
const syntheticGrant = (bunker: string): any => ({ accessToken: "synthetic-access", refreshToken: "synthetic-refresh", bunkerUrl: `bunker://${bunker}?relay=ws%3A%2F%2Flocalhost%3A8080&secret=synthetic-secret`, scope: "policy:synthetic", pubkey: publicKey, authorizationId: 1 });
async function relayBoundary(mode = "valid") {
  const pure = await import("nostr-tools/pure"), { v2 } = await import("nostr-tools/nip44");
  const bunkerKey = pure.generateSecretKey(), userKey = pure.generateSecretKey();
  const bunker = pure.getPublicKey(bunkerKey), user = pure.getPublicKey(userKey);
  const state = { destroyed: 0, closed: 0, handlers: undefined as any };
  const pool = {
    subscribe(_relays: string[], _filter: any, handlers: any) { state.handlers = handlers; return { close() { state.closed++; } }; },
    publish(relays: string[], event: any) {
      expect(relays).toEqual(["ws://localhost:8080"]); expect(event.kind).toBe(24133);
      expect(pure.verifyEvent(JSON.parse(JSON.stringify(event)))).toBe(true);
      const request = JSON.parse(v2.decrypt(event.content, v2.utils.getConversationKey(bunkerKey, event.pubkey)));
      if (request.method === "connect") expect(request.params).toEqual([bunker, "synthetic-secret"]);
      queueMicrotask(() => {
        const active = request.method !== "connect";
        if (active && mode === "drop") { state.handlers.onclose(["private relay failure"]); return; }
        if ((active && mode === "timeout") || (!active && mode === "connect_timeout")) return;
        if (!active && mode === "connect_drop") { state.handlers.onclose(["private connect failure"]); return; }
        let response: any = { id: active && mode === "wrong_id" ? "unrelated-request" : request.id, result: active ? user : "ack" };
        if (!active && mode === "connect_denied") response = { id: request.id, error: "Permission denied: Invalid secret" };
        if (active && mode === "policy") response = { id: request.id, error: "Permission denied: Blocked by 'challenge_actions' policy" };
        if (active && mode === "both") response.error = "denied";
        const key = active && mode === "wrong_bunker" ? userKey : bunkerKey;
        const content = active && mode === "bad_ciphertext" ? "malformed" : v2.encrypt(active && mode === "malformed" ? "{" : JSON.stringify(response), v2.utils.getConversationKey(key, event.pubkey));
        const reply = pure.finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000), tags: [["p", event.pubkey], ["e", event.id]], content }, key);
        if (active && mode === "bad_sig") reply.sig = "0".repeat(128);
        state.handlers.onevent(reply);
      });
      return [Promise.resolve("accepted")];
    },
    destroy() { state.destroyed++; },
  };
  return { state, pool, grant: { ...syntheticGrant(bunker), pubkey: user }, user };
}
test("signed results verify full ID/signature and every frozen field independently", async () => {
  const { verifySignedResult, freezeTemplate } = await rpcModule(), pure = await import("nostr-tools/pure");
  const key = pure.generateSecretKey(), pubkey = pure.getPublicKey(key);
  const template = { pubkey, kind: 1111, created_at: 123, content: "synthetic", tags: [["t", "first"], ["t", "second"], ["challenge_snapshot", '{"signed":"preserve bytes"}']] };
  const expected = freezeTemplate(template), signed = pure.finalizeEvent(structuredClone(template), key);
  expect(() => verifySignedResult(signed, expected, pubkey)).not.toThrow();
  expect(() => verifySignedResult(JSON.stringify(signed), expected, pubkey)).not.toThrow();
  for (const mutation of [{ sig: "0".repeat(128) }, { id: "0".repeat(64) }, { pubkey: pure.getPublicKey(pure.generateSecretKey()) }, { tags: [...template.tags].reverse() }, { content: "changed" }, { created_at: 124 }, { kind: 31923 }]) expect(() => verifySignedResult({ ...signed, ...mutation }, expected, pubkey)).toThrow();
  // Valid signatures over different fields still fail exact-template binding.
  for (const change of [{ kind: 31923 }, { created_at: 124 }, { content: "changed" }, { tags: [...template.tags].reverse() }]) {
    expect(() => verifySignedResult(pure.finalizeEvent({ ...structuredClone(template), ...change }, key), expected, pubkey)).toThrow();
  }
  const otherKey = pure.generateSecretKey();
  expect(() => verifySignedResult(pure.finalizeEvent(structuredClone(template), otherKey), expected, pubkey)).toThrow();
  signed.sig = "0".repeat(128); // Preserve finalizeEvent's cached true stamp.
  expect(() => verifySignedResult(signed, expected, pubkey)).toThrow();
  template.tags[0][1] = "changed caller"; template.content = "changed caller";
  expect(expected.tags[0][1]).toBe("first"); expect(expected.content).toBe("synthetic"); expect(Object.isFrozen(expected.tags[0])).toBe(true);
});
test("HTTP bearer RPC retains HTTP200 explicit errors without a result", async () => {
  const { createRpcAdapters } = await rpcModule();
  const adapter = createRpcAdapters({ fetch: async (url: any, options: any) => {
    expect(url).toBe("http://localhost:3000/api/nostr"); expect(options.headers.Authorization).toBe("Bearer synthetic-access");
    expect(options.redirect).toBe("error"); expect(JSON.parse(options.body)).toEqual({ method: "get_public_key", params: [] });
    return new Response(JSON.stringify({ error: "Operation denied by policy" }), { status: 200 });
  } });
  const outcome = await adapter.httpRpc(syntheticGrant("1".repeat(64)), "get_public_key", []);
  expect(outcome).toEqual({ status: 200, error: "Operation denied by policy" }); expect(outcome).not.toHaveProperty("result");
});
for (const [name, body, status] of [["both", { error: "denied", result: "signed" }, 200], ["hidden_signature", { error: "denied", sig: "0".repeat(128) }, 200], ["empty", {}, 200], ["auth", { error: "Unauthorized" }, 401], ["parse", "{", 200]] as const) test(`HTTP ${name} failure rejects separately`, async () => {
  const { createRpcAdapters } = await rpcModule();
  const adapter = createRpcAdapters({ fetch: async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status }) });
  await expect(adapter.httpRpc(syntheticGrant("1".repeat(64)), "sign_event", [])).rejects.toThrow(/^challenge_image:/);
});
test("HTTP deadline rejects and aborts without returning denial", async () => {
  const { createRpcAdapters } = await rpcModule(); let signal: AbortSignal | undefined;
  const adapter = createRpcAdapters({ requestTimeoutMs: 5, fetch: async (_url: any, options: any) => { signal = options.signal; return new Promise(() => {}); } });
  await expect(adapter.httpRpc(syntheticGrant("1".repeat(64)), "get_public_key", [])).rejects.toThrow("deadline"); expect(signal?.aborted).toBe(true);
});
test("relay SDK connects with bunker secret and returns actual user identity", async () => {
  const { createRpcAdapters } = await rpcModule(), boundary = await relayBoundary();
  const relay = await createRpcAdapters({ pool: () => boundary.pool as any }).openRelay(boundary.grant);
  try { expect(await relay.request("get_public_key", [])).toEqual({ result: boundary.user }); } finally { await relay.close(); }
  expect(boundary.state.closed).toBe(1); expect(boundary.state.destroyed).toBe(1);
});
test("relay explicit policy error contains no successful result", async () => {
  const { createRpcAdapters } = await rpcModule(), boundary = await relayBoundary("policy");
  const relay = await createRpcAdapters({ pool: () => boundary.pool as any }).openRelay(boundary.grant);
  try { expect(await relay.request("sign_event", ["{}"])) .toEqual({ error: "Permission denied: Blocked by 'challenge_actions' policy" }); } finally { await relay.close(); }
});
for (const [mode, category] of Object.entries({ wrong_id: "relay_correlation", wrong_bunker: "relay_sender", bad_sig: "signed_verification", bad_ciphertext: "relay_payload", malformed: "relay_payload", both: "rpc_shape", drop: "relay_closed", timeout: "rpc_deadline" })) test(`relay ${mode} rejects separately and tears down`, async () => {
  const { createRpcAdapters } = await rpcModule(), boundary = await relayBoundary(mode);
  const relay = await createRpcAdapters({ pool: () => boundary.pool as any, requestTimeoutMs: mode === "timeout" ? 10 : 1000 }).openRelay(boundary.grant);
  await expect(relay.request("get_public_key", [])).rejects.toThrow(`challenge_image:${category}`);
  await relay.close(); expect(boundary.state.closed).toBe(1); expect(boundary.state.destroyed).toBe(1);
});

test("HTTP exact signed synthetic response passes independent verification", async () => {
  const { createRpcAdapters, freezeTemplate, verifySignedResult } = await rpcModule(), pure = await import("nostr-tools/pure");
  const key = pure.generateSecretKey(), pubkey = pure.getPublicKey(key);
  const expected = freezeTemplate({ pubkey, kind: 31923, created_at: 123, content: "Synthetic", tags: [["t", "one"], ["t", "two"]] });
  const signed = pure.finalizeEvent(structuredClone(expected), key);
  const adapter = createRpcAdapters({ fetch: async () => new Response(JSON.stringify({ result: signed })) });
  const result = await adapter.httpRpc(syntheticGrant(pubkey), "sign_event", [expected]);
  expect(result.error).toBeUndefined(); expect(() => verifySignedResult(result.result, expected, pubkey)).not.toThrow();
});
test("HTTP deadline bounds response body parsing too", async () => {
  const { createRpcAdapters } = await rpcModule();
  const adapter = createRpcAdapters({ requestTimeoutMs: 5, fetch: async () => ({ status: 200, json: () => new Promise(() => {}) }) as any });
  await expect(adapter.httpRpc(syntheticGrant("1".repeat(64)), "get_public_key", [])).rejects.toThrow("deadline");
});
for (const mode of ["connect_timeout", "connect_drop", "connect_denied"]) test(`relay ${mode} rejects and closes the initial connection`, async () => {
  const { createRpcAdapters } = await rpcModule(), boundary = await relayBoundary(mode);
  await expect(createRpcAdapters({ pool: () => boundary.pool as any, connectTimeoutMs: 10 }).openRelay(boundary.grant)).rejects.toThrow(/^challenge_image:/);
  expect(boundary.state.closed).toBe(1); expect(boundary.state.destroyed).toBe(1);
});
