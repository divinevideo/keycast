import { test } from "@playwright/test";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { generateSecretKey, getPublicKey, getEventHash } from "nostr-tools/pure";
import * as nip04 from "nostr-tools/nip04";
import { v2 } from "nostr-tools/nip44";
import { wrapEvent } from "nostr-tools/nip17";
import { createRumor } from "nostr-tools/nip59";
import { assertOwnedFixture, configFromEnvironment, preparePolicies, registerSyntheticUser, issueGrant, type Grant, type FixtureConfig, type PolicyFixtures, type SessionFixture } from "../helpers/challenge-image-fixtures";
import { httpRpc, openRelay, freezeTemplate, verifySignedResult, type SigningTemplate, type RpcOutcome } from "../helpers/challenge-image-rpc";

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
const cases: { id: string; passed: boolean }[] = [];
const ensure = (ok: unknown, category: string): void => { if (!ok) throw new Error(`challenge_image:${category}`); };
async function saveSummary() {
  await writeFile("/tmp/challenge-image-summary.json", JSON.stringify({ schema_version: 1, cases }), { mode: 0o600 });
}
// Task 4 records only its real consent/hold operations through this same hook.
// No runtime-owned IDs or stand-ins are ever written by the client suite.
export async function recordCase(id: string, operation: () => Promise<void>): Promise<void> {
  ensure(!cases.some(c => c.id === id), "case_duplicate");
  const row = { id, passed: false }; cases.push(row);
  try { await operation(); row.passed = true; }
  catch { throw new Error("challenge_image:case_failed"); }
  finally { await saveSummary(); }
}
let config: FixtureConfig, policies: PolicyFixtures, session: SessionFixture;
let canonical: Record<string, SigningTemplate>;
test.beforeAll(async ({ playwright }) => {
  // Always attempt the strict summary, even if fixture initialization fails.
  await saveSummary();
  config = configFromEnvironment(); await assertOwnedFixture(config);
  const request = await playwright.request.newContext({ baseURL: config.baseUrl, timeout: 15000 });
  try {
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
test.afterAll(async () => { await saveSummary(); });
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
