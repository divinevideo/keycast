import { test, type APIRequestContext, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { generateSecretKey, getPublicKey, getEventHash } from "nostr-tools/pure";
import * as nip04 from "nostr-tools/nip04";
import { v2 } from "nostr-tools/nip44";
import { wrapEvent } from "nostr-tools/nip17";
import { createRumor } from "nostr-tools/nip59";
import {
  assertOwnedFixture, configFromEnvironment, preparePolicies, registerSyntheticUser, issueGrant,
  withPermissionMutation, assertPolicyUnchanged, assertNoGlobalChallenges, prepareAuthorization,
  issueAuthorizationCode, exchangeAuthorization, refreshGrant, codeState, assertRefreshState, teamPolicyCounts,
  assertEmptyConsentDisplay, CONSENT_CASE_IDS, MALFORMED_PERMISSIONS, CONFIG_BOUNDARIES, CHALLENGE_TITLE, CHALLENGE_PHRASES,
  type Grant, type FixtureConfig, type PolicyFixtures, type SessionFixture, type PolicyFixture,
} from "../helpers/challenge-image-fixtures";
import { httpRpc, openRelay, freezeTemplate, verifySignedResult, type SigningTemplate, type RpcOutcome } from "../helpers/challenge-image-rpc";
import { createSummaryRecorder } from "../helpers/challenge-image-summary";

// Deliberately no top-level I/O: --list must collect without any connection,
// fixture read, environment requirement, global setup or browser launch.
export const SIGNING_CASES = [
  "get_public_key", "definition", "entry", "withdraw", "result", "contest_include", "contest_exclude",
  "denied_kind_0", "denied_kind_1", "denied_kind_4", "denied_kind_21", "denied_kind_22", "denied_kind_44", "denied_kind_1059", "denied_kind_22242", "denied_kind_27235", "denied_kind_34235", "denied_kind_34236",
  "unmarked_31923", "unmarked_1111", "unmarked_1985", "mismatched_contest_namespace", "bad_embedded_snapshot",
  "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt", "sign_canonical", "nip17_wrap_batch", "nip17_unwrap_batch", "empty_policy_control", "and_policy_control",
] as const;
type Transport = "http" | "nip46";
type RequestRpc = (method: string, params: unknown[]) => Promise<RpcOutcome>;
const ensure = (ok: unknown, category: string): void => { if (!ok) throw new Error(`challenge_image:${category}`); };
const summary = createSummaryRecorder([
  ...["http", "nip46"].flatMap(transport => SIGNING_CASES.map(name => `signing.${transport}.${name}`)),
  ...CONSENT_CASE_IDS,
]);
export function recordCase(id: string, operation: () => Promise<void>): Promise<void> {
  // Status is the framework's authoritative cancellation guard (its budget
  // also includes fixture setup). The local deadline additionally bounds this
  // body even while Playwright is gracefully stopping an expired worker.
  const info = test.info(), deadline = performance.now() + info.timeout;
  return summary.recordCase(id, operation, { canPass: () =>
    info.status === "passed" && performance.now() < deadline });
}
let config: FixtureConfig, policies: PolicyFixtures, session: SessionFixture;
let canonical: Record<string, SigningTemplate>;
test.beforeAll(async ({ playwright }) => {
  // Always attempt the strict summary, even if fixture initialization fails.
  await summary.initialize();
  config = configFromEnvironment(); await assertOwnedFixture(config);
  const request = await playwright.request.newContext({ baseURL: config.baseUrl, timeout: 15000 });
  try {
    await noGlobalChallenges(request); // Must run before the first synthetic seed.
    policies = await preparePolicies(config);
    session = await registerSyntheticUser(request, config);
    const fixture = JSON.parse(await readFile(path.resolve(__dirname, "../../core/tests/fixtures/challenges/v1/events.json"), "utf8"));
    ensure(fixture.version === 1 && fixture.synthetic === true && Array.isArray(fixture.cases), "canonical_fixture");
    canonical = Object.fromEntries(["definition", "entry", "withdraw", "result"].map(name => {
      const matches = fixture.cases.filter((c: any) => c.name === name);
      ensure(matches.length === 1, "canonical_fixture");
      const event = structuredClone(matches[0].event); delete event.id; delete event.sig;
      event.pubkey = session.pubkey;
      return [name, freezeTemplate(event)];
    }));
  } finally { await request.dispose(); }
});
test.afterAll(async () => { await summary.initialize(); await summary.assertComplete(); });
function ordinary(grant: Grant, kind = 1): SigningTemplate {
  return freezeTemplate({ pubkey: grant.pubkey, kind, created_at: Math.floor(Date.now() / 1000), content: kind === 0 ? "{}" : "Synthetic acceptance", tags: [] });
}
function curation(grant: Grant, action: "include" | "exclude"): SigningTemplate {
  const namespace = "video.divine.contest.Synthetic:é";
  return freezeTemplate({ ...ordinary(grant, 1985), content: "", tags: [["L", namespace], ["l", action, namespace], ["e", "11".repeat(32), "wss://relay.example"], ["a", `34235:${"22".repeat(32)}:synthetic`]] });
}
function success(response: RpcOutcome, transport: Transport): unknown {
  ensure(response.error === undefined && Object.hasOwn(response, "result") && (transport !== "http" || response.status === 200), "rpc_success");
  return response.result;
}
function policyDenial(response: RpcOutcome, transport: Transport, permission = "challenge_actions"): void {
  ensure(!Object.hasOwn(response, "result") && (transport === "http"
    ? response.status === 403 && response.error === "Operation denied by policy"
    : response.status === undefined && response.error === `Permission denied: Blocked by '${permission}' policy`), "policy_denial");
}
async function sign(rpc: RequestRpc, transport: Transport, grant: Grant, template: SigningTemplate): Promise<void> {
  const expected = freezeTemplate(template); // Freeze before the asynchronous call.
  verifySignedResult(success(await rpc("sign_event", [expected]), transport), expected, grant.pubkey);
}
async function execute(name: typeof SIGNING_CASES[number], transport: Transport, grant: Grant, rpc: RequestRpc): Promise<void> {
  if (name === "get_public_key") { ensure(success(await rpc("get_public_key", []), transport) === session.pubkey, "signer_identity"); return; }
  if (["definition", "entry", "withdraw", "result"].includes(name)) { await sign(rpc, transport, grant, canonical[name]); return; }
  if (name === "contest_include" || name === "contest_exclude") { await sign(rpc, transport, grant, curation(grant, name === "contest_include" ? "include" : "exclude")); return; }
  if (name.startsWith("denied_kind_")) { policyDenial(await rpc("sign_event", [ordinary(grant, Number(name.slice("denied_kind_".length)))]), transport); return; }
  if (name.startsWith("unmarked_")) {
    policyDenial(await rpc("sign_event", [freezeTemplate({ ...canonical.definition, kind: Number(name.slice("unmarked_".length)), tags: [] })]), transport); return;
  }
  if (name === "mismatched_contest_namespace") {
    const bad = structuredClone(curation(grant, "include")); bad.tags[1][2] = "video.divine.contest.other";
    policyDenial(await rpc("sign_event", [freezeTemplate(bad)]), transport); return;
  }
  if (name === "bad_embedded_snapshot") {
    const bad = structuredClone(canonical.entry), tag = bad.tags.find(t => t[0] === "challenge_snapshot")!;
    const snapshot = JSON.parse(tag[1]); snapshot.content = "Synthetic tampering"; tag[1] = JSON.stringify(snapshot);
    policyDenial(await rpc("sign_event", [freezeTemplate(bad)]), transport); return;
  }
  if (name === "and_policy_control") {
    await sign(rpc, transport, grant, canonical.definition);
    policyDenial(await rpc("sign_event", [canonical.entry]), transport, "allowed_kinds"); return;
  }
  const peerSecret = generateSecretKey(), peer = getPublicKey(peerSecret), plaintext = "Synthetic encryption control";
  if (name === "empty_policy_control") {
    await sign(rpc, transport, grant, ordinary(grant));
    for (const family of ["nip04", "nip44"] as const) {
      const encrypted = success(await rpc(`${family}_encrypt`, [peer, plaintext]), transport);
      ensure(typeof encrypted === "string", "encryption_result");
      const opened = family === "nip04" ? await nip04.decrypt(peerSecret, grant.pubkey, encrypted as string) : v2.decrypt(encrypted as string, v2.utils.getConversationKey(peerSecret, grant.pubkey));
      ensure(opened === plaintext, "encryption_roundtrip");
      const incoming = family === "nip04" ? await nip04.encrypt(peerSecret, grant.pubkey, plaintext) : v2.encrypt(plaintext, v2.utils.getConversationKey(peerSecret, grant.pubkey));
      ensure(success(await rpc(`${family}_decrypt`, [peer, incoming]), transport) === plaintext, "decryption_roundtrip");
    }
    return;
  }
  if (name.startsWith("nip04_") || name.startsWith("nip44_")) {
    const decrypt = name.endsWith("decrypt"), legacy = name.startsWith("nip04");
    const input = decrypt ? (legacy ? await nip04.encrypt(peerSecret, grant.pubkey, plaintext) : v2.encrypt(plaintext, v2.utils.getConversationKey(peerSecret, grant.pubkey))) : plaintext;
    policyDenial(await rpc(name, [peer, input]), transport);
    if (decrypt) policyDenial(await rpc(name, [peer, "malformed ciphertext control"]), transport);
    return;
  }
  if (name === "sign_canonical") {
    const payload = Buffer.from(JSON.stringify({ version: 1, pubkey: grant.pubkey, sig_alg: "nostr.secp256k1", created_at: "2026-04-29T00:00:00Z", claims: { nip05: "creator@example.com", website: "https://example.com" }, referenced_assertions: ["c2pa.actions.v2", "cawg.training-mining"], hard_binding: { alg: "sha256", value: "39341a12a2f77007d6e72841f667523d39463a825d82c6c98981881283fb7ed0" } })).toString("base64");
    const response = await rpc(name, [payload]);
    if (transport === "http") policyDenial(response, transport);
    else ensure(!Object.hasOwn(response, "result") && response.error === `Unsupported method: ${name}`, "unsupported_method");
    return;
  }
  if (name === "nip17_wrap_batch" || name === "nip17_unwrap_batch") {
    // Rumors are unsigned: set the real signer author and recompute their ID.
    const rumor = createRumor({ kind: 14, created_at: Math.floor(Date.now() / 1000), content: plaintext, tags: [["p", peer]] }, peerSecret);
    rumor.pubkey = grant.pubkey; rumor.id = getEventHash(rumor);
    const params = name === "nip17_wrap_batch" ? [rumor, [peer, peer]] : [wrapEvent(peerSecret, { publicKey: grant.pubkey }, plaintext), wrapEvent(peerSecret, { publicKey: grant.pubkey }, plaintext)];
    const response = await rpc(name, params);
    if (transport === "nip46") ensure(!Object.hasOwn(response, "result") && response.error === `Unsupported method: ${name}`, "unsupported_method");
    else {
      const slots = success(response, transport);
      ensure(Array.isArray(slots) && slots.length === 2 && slots.every(slot => slot && Object.keys(slot).length === 1 && slot.error === "permission_denied"), "batch_policy_denial");
    }
    return;
  }
  throw new Error("challenge_image:unknown_case");
}
for (const transport of ["http", "nip46"] as const) for (const name of SIGNING_CASES) {
  const id = `signing.${transport}.${name}`;
  test(id, async ({ request }) => recordCase(id, async () => {
    await assertOwnedFixture(config);
    const policy = name === "empty_policy_control" ? policies.empty : name === "and_policy_control" ? policies.intersection : policies.restricted;
    // Each relay client needs a fresh authorization: bunker secrets bind a
    // single client. Retain the original owned policy and session objects.
    const grant = await issueGrant(request, session, policy);
    if (transport === "http") await execute(name, transport, grant, (method, params) => httpRpc(grant, method, params));
    else {
      const relay = await openRelay(grant);
      try {
        await execute(name, transport, grant, (method, params) => relay.request(method, params.map(value => typeof value === "string" ? value : JSON.stringify(value))));
      } finally { await relay.close(); }
    }
  }));
}

async function localJson(request: APIRequestContext, method: "get" | "post", route: string, data?: unknown, cookie?: string) {
  const response = await request[method](config.baseUrl + route, { data, timeout: 15000, maxRedirects: 0,
    headers: { Origin: config.baseUrl, ...(cookie ? { Cookie: cookie } : {}) } });
  return { status: response.status(), body: await response.json() };
}
async function noGlobalChallenges(request: APIRequestContext): Promise<void> {
  await assertNoGlobalChallenges(config);
  const result = await localJson(request, "get", "/api/policies");
  ensure(result.status === 200 && Array.isArray(result.body.policies)
    && result.body.policies.every((p: any) => p.slug !== "challenges"), "global_preset_absent");
}
async function signedIn(page: Page): Promise<void> {
  await page.context().addCookies([{ name: "keycast_session", value: session.cookie.slice("keycast_session=".length), url: config.baseUrl }]);
}
async function renderedGrant(page: Page, request: APIRequestContext, policy: PolicyFixture): Promise<Grant> {
  const auth = await prepareAuthorization(session, policy);
  await signedIn(page);
  const response = await page.goto(auth.url);
  ensure(response?.status() === 200, "consent_page");
  const authorize = page.getByRole("button", { name: "Authorize", exact: true });
  await authorize.waitFor({ state: "visible" });
  if (policy.kind === "empty") {
    await page.getByRole("heading", { name: "App Access", exact: true }).waitFor({ state: "visible" });
    await page.getByText("Grant this application access to your account", { exact: true }).waitFor({ state: "visible" });
    assertEmptyConsentDisplay({
      items: await page.locator(".permission_item").evaluateAll(nodes => nodes.map(node => ({
        headings: Array.from(node.querySelectorAll("h3"), heading => heading.textContent?.trim() ?? ""),
        descriptions: Array.from(node.querySelectorAll("p"), paragraph => paragraph.textContent?.trim() ?? ""),
      }))),
      text: await page.locator("body").innerText(),
    });
  }
  else {
    await page.getByRole("heading", { name: CHALLENGE_TITLE, exact: true }).waitFor({ state: "visible" });
    ensure(await page.locator(".permission_item").count() === 1, "consent_display_count");
    for (const phrase of CHALLENGE_PHRASES) await page.getByText(phrase, { exact: false }).waitFor({ state: "visible" });
  }
  let code = "";
  await page.route(config.baseUrl + "/acceptance-callback?*", async route => {
    const url = new URL(route.request().url());
    code = url.searchParams.get("code") ?? "";
    await route.fulfill({ status: 200, contentType: "text/plain", body: "Synthetic acceptance callback" });
  });
  try {
    await Promise.all([page.waitForURL(url => url.origin === config.baseUrl && url.pathname === "/acceptance-callback"), authorize.click()]);
    ensure(typeof code === "string" && code.length > 0, "consent_code");
    return await exchangeAuthorization(request, auth, code!);
  } finally { await page.unroute(config.baseUrl + "/acceptance-callback?*"); }
}
async function restrictedBoundary(grant: Grant): Promise<void> {
  ensure(success(await httpRpc(grant, "get_public_key", []), "http") === session.pubkey, "consent_signer");
  await sign((method, params) => httpRpc(grant, method, params), "http", grant, canonical.definition);
  policyDenial(await httpRpc(grant, "sign_event", [ordinary(grant)]), "http");
}
for (const empty of [false, true]) for (const refresh of [false, true]) {
  const id = `consent.${empty ? "empty-" : ""}${refresh ? "refresh" : "authorize"}`;
  test(id, async ({ page, request }) => recordCase(id, async () => {
    const policy = empty ? policies.empty : policies.restricted;
    const original = await renderedGrant(page, request, policy);
    const grant = refresh ? await refreshGrant(request, original) : original;
    ensure(grant.scope === policy.scope, "consent_scope");
    if (refresh) {
      await assertRefreshState(original, true, 2);
      await assertRefreshState(grant, false, 2);
    }
    await assertPolicyUnchanged(policy);
    if (empty) {
      await sign((method, params) => httpRpc(grant, method, params), "http", grant, ordinary(grant));
    } else await restrictedBoundary(grant);
  }));
}
function permissionLoadError(result: { status: number; body: any }, policyApi = false): void {
  ensure(result.status === 500 && !Object.hasOwn(result.body, "result")
    && (policyApi ? result.body.error === "permission_error" && result.body.message === "Configured permission could not be loaded"
      : result.body.error === "Server error: Configured permission could not be loaded"), "permission_load_error");
}
async function healthyControl(request: APIRequestContext, grant: Grant): Promise<void> {
  ensure(success(await httpRpc(grant, "get_public_key", []), "http") === session.pubkey, "healthy_rpc");
  const result = await localJson(request, "get", "/api/policies");
  ensure(result.status === 200 && Array.isArray(result.body.policies), "healthy_policies");
}
for (const [name, identifier, configText] of MALFORMED_PERMISSIONS) for (const boundary of CONFIG_BOUNDARIES) {
  const id = `config.${name}.${boundary}`;
  test(id, async ({ page, request }) => recordCase(id, async () => {
    // Fresh owned policy and authorization: no HTTP signer has cached it before
    // the mutation. Invalid global display configuration is always serial.
    const policy = (await preparePolicies(config)).restricted;
    const grant = await issueGrant(request, session, policy);
    const control = await issueGrant(request, session, policies.restricted);
    const pending = boundary === "exchange" ? await issueAuthorizationCode(request, session, policy) : undefined;
    const beforeCode = pending ? await codeState(pending.auth, pending.code) : undefined;
    if (pending) ensure(beforeCode?.authorizations === 0 && beforeCode.refreshTokens === 0, "code_initial_state");
    if (boundary === "refresh") await assertRefreshState(grant, false);
    const consent = boundary === "consent" ? await prepareAuthorization(session, policy) : undefined;
    await healthyControl(request, control);
    try {
      await withPermissionMutation(policy, identifier, configText, async () => {
        if (boundary === "http") {
          const outcome = await httpRpc(grant, "get_public_key", []);
          ensure(outcome.status === 500 && !Object.hasOwn(outcome, "result")
            && outcome.error === "Configured permission could not be loaded", "cold_handler_failure");
        } else if (boundary === "detail" || boundary === "list") {
          permissionLoadError(await localJson(request, "get", boundary === "list" ? "/api/policies" : `/api/policies/${policy.slug}`), true);
        } else if (boundary === "consent") {
          await signedIn(page);
          const response = await page.goto(consent!.url);
          ensure(response?.status() === 500, "malformed_consent_status");
          await page.getByText("Configured permission could not be loaded", { exact: false }).waitFor({ state: "visible" });
          ensure(await page.getByRole("button", { name: "Authorize", exact: true }).count() === 0
            && await page.locator(".btn_approve, form").count() === 0, "malformed_consent_approval");
        } else {
          const result = await localJson(request, "post", "/api/oauth/token", pending ? {
            grant_type: "authorization_code", code: pending.code, client_id: pending.auth.clientId,
            redirect_uri: pending.auth.redirectUri, code_verifier: pending.auth.verifier,
          } : { grant_type: "refresh_token", refresh_token: grant.refreshToken, client_id: grant.clientId });
          permissionLoadError(result);
          ensure(["access_token", "refresh_token", "bunker_url"].every(key => !Object.hasOwn(result.body, key)), "rejected_credentials");
          if (pending) {
            // Code redemption is released on display failure. An in-memory
            // UCAN may already have been generated; no credential row is added.
            const after = await codeState(pending.auth, pending.code);
            ensure(after.authorizations === beforeCode!.authorizations && after.refreshTokens === beforeCode!.refreshTokens, "code_rows_unchanged");
          } else {
            // Refresh consumption precedes display and is intentionally retained.
            await assertRefreshState(grant, true);
          }
        }
      });
    } finally {
      await healthyControl(request, control);
      await assertPolicyUnchanged(policy);
    }
  }));
}
test("management.creation-held", async ({ request }) => recordCase("management.creation-held", async () => {
  const before = await teamPolicyCounts(session);
  const result = await localJson(request, "post", `/api/teams/${session.teamId}/policies`, {
    name: "Synthetic challenge hold", permissions: [{ identifier: "challenge_actions", config: {} }],
  }, session.cookie);
  ensure(result.status === 400 && result.body.error === "This permission is not currently available for team policies", "creation_hold");
  const after = await teamPolicyCounts(session);
  ensure(after.policies === before.policies && after.permissions === before.permissions && after.links === before.links, "creation_hold_rows");
}));
test("management.allowed-kinds-control", async ({ request }) => recordCase("management.allowed-kinds-control", async () => {
  const before = await teamPolicyCounts(session);
  const result = await localJson(request, "post", `/api/teams/${session.teamId}/policies`, {
    name: "Synthetic allowed kinds control", permissions: [{ identifier: "allowed_kinds", config: { allowed_kinds: [31923] } }],
  }, session.cookie);
  ensure(result.status === 200 && result.body.policy?.team_id === session.teamId
    && result.body.permissions?.length === 1 && result.body.permissions[0].identifier === "allowed_kinds", "management_control");
  const after = await teamPolicyCounts(session);
  ensure(after.policies === before.policies + 1 && after.permissions === before.permissions + 1 && after.links === before.links + 1, "management_control_rows");
}));
test("management.picker", async ({ page }) => recordCase("management.picker", async () => {
  await signedIn(page);
  const response = await page.goto(`${config.baseUrl}/teams/${session.teamId}/policies/new`);
  ensure(response?.status() === 200, "picker_page");
  ensure(await page.evaluate(() => (window as any).__ENV__?.SHOW_TEAMS_FUNCTIONALITY === "true"), "picker_runtime_flag");
  const select = page.locator("select");
  await select.waitFor({ state: "visible" });
  ensure(await select.isEnabled(), "picker_enabled");
  ensure(await select.locator('option[value="challenge_actions"]').count() === 0, "picker_hold");
  await select.selectOption("allowed_kinds");
  ensure(await select.inputValue() === "allowed_kinds", "picker_selection");
  await page.getByText("Which kinds are allowed for each permission type", { exact: false }).waitFor({ state: "visible" });
}));
test("management.no-global-preset", async ({ request }) => recordCase("management.no-global-preset", async () => {
  await noGlobalChallenges(request);
}));
