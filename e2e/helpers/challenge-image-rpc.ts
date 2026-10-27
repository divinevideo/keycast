import WebSocket from "ws";
import { BunkerSigner, parseBunkerInput } from "nostr-tools/nip46";
import { SimplePool, useWebSocketImplementation, type AbstractSimplePool } from "nostr-tools/pool";
import { generateSecretKey, getPublicKey, verifyEvent, getEventHash, type EventTemplate, type NostrEvent } from "nostr-tools/pure";
import { v2 } from "nostr-tools/nip44";
import type { Grant } from "./challenge-image-fixtures";

export interface RpcOutcome { status?: number; result?: unknown; error?: string }
export interface RelayRpc { request(method: string, params: string[]): Promise<RpcOutcome>; close(): Promise<void> }
export type SigningTemplate = EventTemplate & { pubkey: string };
const fail = (category: string): never => { throw new Error(`challenge_image:${category}`); };
function check(value: unknown, category: string): asserts value { if (!value) fail(category); }
const record = (value: unknown): value is Record<string, any> => !!value && typeof value === "object" && !Array.isArray(value);

// Clone before verifying: nostr-tools caches validity on a Symbol. A mutated
// object carrying that cache must never bypass signature or field comparison.
function freshEvent(value: unknown): NostrEvent {
  try {
    const e = typeof value === "string" ? JSON.parse(value) : JSON.parse(JSON.stringify(value));
    check(record(e) && /^[0-9a-f]{64}$/.test(e.id) && /^[0-9a-f]{128}$/.test(e.sig), "signed_shape");
    check(verifyEvent(e as NostrEvent) && getEventHash(e as NostrEvent) === e.id, "signed_signature");
    return e as NostrEvent;
  } catch { return fail("signed_verification"); }
}
export function freezeTemplate(template: SigningTemplate): SigningTemplate {
  const copy: SigningTemplate = JSON.parse(JSON.stringify(template));
  check(record(copy) && !("id" in copy) && !("sig" in copy), "template_shape");
  copy.tags.forEach((tag: string[]) => Object.freeze(tag)); Object.freeze(copy.tags);
  return Object.freeze(copy);
}
export function verifySignedResult(result: unknown, template: SigningTemplate, expectedPubkey: string): void {
  const event = freshEvent(result);
  check(event.pubkey === expectedPubkey && event.kind === template.kind && event.created_at === template.created_at
    && event.content === template.content && JSON.stringify(event.tags) === JSON.stringify(template.tags), "signed_fields");
}
function outcome(body: unknown, relayId?: string): RpcOutcome {
  check(record(body), "rpc_shape");
  if (relayId !== undefined) check(body.id === relayId, "relay_correlation");
  const error = Object.hasOwn(body, "error"), result = Object.hasOwn(body, "result");
  check(error !== result && Object.keys(body).length === (relayId === undefined ? 1 : 2), "rpc_shape");
  if (error) { check(typeof body.error === "string" && body.error.length > 0, "rpc_shape"); return { error: body.error }; }
  check(body.result !== null && body.result !== undefined, "rpc_shape");
  return { result: body.result };
}
async function bounded<T>(operation: Promise<T>, milliseconds: number, onDeadline: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => { onDeadline(); reject(new Error("challenge_image:rpc_deadline")); }, milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}
function sanitized(error: unknown, fallback: string): Error {
  return error instanceof Error && /^challenge_image:[a-z_]+$/.test(error.message) ? error : new Error(`challenge_image:${fallback}`);
}

// External I/O seam for pure contracts. Defaults always use the real HTTP
// transport and the locked SDK's public sendRequest(method, string[]) API.
export function createRpcAdapters(io: { fetch?: typeof fetch; pool?: () => AbstractSimplePool; requestTimeoutMs?: number; connectTimeoutMs?: number } = {}) {
  const requestTimeout = io.requestTimeoutMs ?? 15000, connectTimeout = io.connectTimeoutMs ?? 30000;
  async function httpRpc(grant: Grant, method: string, params: unknown[]): Promise<RpcOutcome> {
    const controller = new AbortController();
    // Serialize now so caller mutations during network awaits cannot alter input.
    const body = JSON.stringify({ method, params });
    try {
      return await bounded((async () => {
        const response = await (io.fetch ?? fetch)("http://localhost:3000/api/nostr", {
          method: "POST", redirect: "error", signal: controller.signal,
          headers: { Authorization: `Bearer ${grant.accessToken}`, "Content-Type": "application/json", Origin: "http://localhost:3000" }, body,
        });
        check(response.status !== 401, "rpc_authentication");
        return { status: response.status, ...outcome(await response.json()) };
      })(), requestTimeout, () => controller.abort());
    } catch (error) { throw sanitized(error, "http_transport"); }
    finally { controller.abort(); }
  }
  async function openRelay(grant: Grant): Promise<RelayRpc> {
    // Validate before parseBunkerInput, which also supports network NIP-05 lookup.
    let url: URL;
    try { url = new URL(grant.bunkerUrl); } catch { return fail("bunker_shape"); }
    check(url.protocol === "bunker:" && /^[0-9a-f]{64}$/.test(url.hostname) && !url.username && !url.password
      && !url.port && !url.pathname && !url.hash && url.searchParams.getAll("relay").length === 1
      && url.searchParams.get("relay") === "ws://localhost:8080" && url.searchParams.getAll("secret").length === 1
      && url.searchParams.get("secret") && [...url.searchParams.keys()].every(k => k === "relay" || k === "secret"), "bunker_shape");
    const pointer = await parseBunkerInput(grant.bunkerUrl);
    check(pointer && pointer.pubkey === url.hostname && pointer.relays.length === 1 && pointer.relays[0] === "ws://localhost:8080"
      && pointer.secret === url.searchParams.get("secret"), "bunker_shape");
    useWebSocketImplementation(WebSocket);
    const secret = generateSecretKey(), client = getPublicKey(secret);
    let conversation: Uint8Array;
    try { conversation = v2.utils.getConversationKey(secret, pointer.pubkey); } catch { return fail("bunker_key"); }
    const pool = io.pool?.() ?? new SimplePool({ enableReconnect: false, enablePing: false });
    let signer: BunkerSigner | undefined, closed = false, fault: Error | undefined;
    type Pending = { id?: string; eventId?: string; reply?: RpcOutcome; reject(error: Error): void };
    let pending: Pending | undefined;
    const broken = (error: unknown) => {
      if (closed) return;
      fault = sanitized(error, "relay_transport"); pending?.reject(fault);
    };
    // Retain SDK request serialization, signing, encryption and listener lookup.
    // Guard its pool boundary before its unbounded JSON/error handling runs.
    const guarded = {
      subscribe(relays: string[], filter: any, handlers: any) {
        return pool.subscribe(relays, filter, { ...handlers,
          onevent(value: unknown) {
            try {
              const event = freshEvent(value);
              check(event.kind === 24133 && event.pubkey === pointer.pubkey
                && event.tags.filter(t => t[0] === "p").length === 1 && event.tags.some(t => t[0] === "p" && t[1] === client), "relay_sender");
              check(pending?.id && event.tags.filter(t => t[0] === "e").length === 1
                && event.tags.some(t => t[0] === "e" && t[1] === pending!.eventId), "relay_correlation");
              let body: unknown;
              try { body = JSON.parse(v2.decrypt(event.content, conversation)); } catch { return fail("relay_payload"); }
              const reply = outcome(body, pending.id);
              check(reply.error !== undefined || (typeof reply.result === "string" && reply.result.length > 0 && reply.result !== "auth_url"), "relay_result");
              check(!pending.reply, "relay_duplicate"); pending.reply = reply;
              // Already parsed/verified above; this callback cannot encounter a
              // malformed envelope or unexpected auth_url diagnostic path.
              void handlers.onevent(event);
            } catch (error) { broken(error); }
          },
          onclose() { broken(new Error("challenge_image:relay_closed")); },
        });
      },
      publish(relays: string[], event: NostrEvent) {
        try {
          check(pending && event.kind === 24133 && event.pubkey === client, "relay_request");
          const request = JSON.parse(v2.decrypt(event.content, conversation));
          check(typeof request.id === "string", "relay_request");
          pending.id = request.id; pending.eventId = event.id;
          return pool.publish(relays, event);
        } catch (error) { broken(error); return [Promise.reject(new Error("challenge_image:relay_request"))]; }
      },
    } as unknown as AbstractSimplePool;
    async function close(): Promise<void> {
      if (closed) return; closed = true;
      pending?.reject(new Error("challenge_image:relay_closed"));
      try { await signer?.close(); } finally { pool.destroy(); }
    }
    async function request(method: string, params: string[], deadline = requestTimeout): Promise<RpcOutcome> {
      check(!closed && !pending && !fault, "relay_unavailable");
      const copy = [...params];
      let reject!: (error: Error) => void;
      const failure = new Promise<never>((_, fail) => { reject = fail; });
      const active: Pending = { reject }; pending = active;
      try {
        const result = await bounded(Promise.race([signer!.sendRequest(method, copy), failure]), deadline, () => {});
        check(active.reply && !active.reply.error && result === active.reply.result, "relay_result");
        return active.reply;
      } catch (error) {
        if (!fault && active.reply?.error && error === active.reply.error) return active.reply;
        await close(); throw sanitized(error, "relay_transport");
      } finally { pending = undefined; }
    }
    try {
      signer = BunkerSigner.fromBunker(secret, pointer, { pool: guarded });
      const connected = await request("connect", [pointer.pubkey, pointer.secret!], connectTimeout);
      check(connected.result === "ack" && connected.error === undefined, "relay_connect");
      return { request, close };
    } catch (error) { await close(); throw sanitized(error, "relay_connect"); }
  }
  return { httpRpc, openRelay };
}
export const { httpRpc, openRelay } = createRpcAdapters();
