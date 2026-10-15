#!/usr/bin/env bun
// Local acceptance test: real HTTP accounts and NIP-46 through a real relay.
// Credentials remain in memory. Use a disposable local database behind the API.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { getConversationKey, encrypt, decrypt } from 'nostr-tools/nip44';
import WebSocket from 'ws';

class DemoFailure extends Error {}
const check = (condition, message) => { if (!condition) throw new DemoFailure(message); };
function localUrl(value, protocols, label) {
  let url;
  try { url = new URL(value); } catch { throw new DemoFailure(`${label} must be an explicit loopback URL`); }
  check(protocols.includes(url.protocol), `${label} has an unsupported protocol`);
  check(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), `${label} must use a literal loopback host`);
  check(!url.username && !url.password, `${label} must not include URL credentials`);
  check(!url.search && !url.hash && url.pathname === '/', `${label} must be an origin URL`);
  return url;
}
let apiUrl;
let relayUrl;
const sockets = new Set();
const timeoutMs = 15_000;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function api(path, { method = 'GET', token, data, expected = 200 } = {}) {
  const response = await fetch(new URL(path, apiUrl), {
    method, redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
  check(response.status === expected, `HTTP ${method} ${path.replace(/[0-9a-f]{64}/g, 'synthetic-admin')}: expected ${expected}, received ${response.status}`);
  const body = await response.json();
  return { body, response };
}

async function register(index, runId) {
  const email = `group-flow-${runId}-${index}@example.invalid`;
  const { body: registered } = await api('/api/auth/register', {
    method: 'POST', data: { email, password: `Synthetic-group-${randomUUID()}!` },
  });
  check(registered.success && /^[0-9a-f]{64}$/.test(registered.pubkey), 'Registration must create a synthetic account');
  check(registered.verification_required === true, 'Registration must require normal email verification');
  let verificationToken;
  for (let attempt = 0; attempt < 20 && !verificationToken; attempt++) {
    const { body: inbox } = await api('/api/dev/emails');
    const captured = inbox.findLast((message) => message.to === email && message.verification_url);
    if (captured) {
      const url = new URL(captured.verification_url);
      check(url.origin === apiUrl.origin, 'Development verification must stay on the local API origin');
      verificationToken = url.searchParams.get('token');
    } else {
      await pause(100);
    }
  }
  check(verificationToken, 'Development inbox must contain the account verification link');
  const { response } = await api('/api/auth/verify-email', { method: 'POST', data: { token: verificationToken } });
  const token = response.headers.get('set-cookie')?.match(/keycast_session=([^;]+)/)?.[1];
  check(token, 'Normal email verification must issue a UCAN session');
  return { pubkey: registered.pubkey, token };
}

class Relay {
  constructor(socket) {
    this.socket = socket;
    this.listeners = new Set();
    socket.on('message', (data) => {
      let frame;
      try { frame = JSON.parse(data.toString()); } catch { return; }
      for (const listener of [...this.listeners]) listener(frame);
    });
    socket.on('error', () => {});
  }
  static async open() {
    const socket = new WebSocket(relayUrl.href);
    sockets.add(socket);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new DemoFailure('Local relay connection timed out')), timeoutMs);
      socket.once('open', () => { clearTimeout(timer); resolve(); });
      socket.once('error', () => { clearTimeout(timer); reject(new DemoFailure('Local relay connection failed')); });
    });
    return new Relay(socket);
  }
  wait(label, select) {
    let listener;
    let timer;
    const promise = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        this.listeners.delete(listener);
        reject(new DemoFailure(`${label} timed out`));
      }, timeoutMs);
      listener = (frame) => {
        try {
          const value = select(frame);
          if (value === undefined) return;
          clearTimeout(timer);
          this.listeners.delete(listener);
          resolve(value);
        } catch {
          clearTimeout(timer);
          this.listeners.delete(listener);
          reject(new DemoFailure(`${label} failed validation`));
        }
      };
      this.listeners.add(listener);
    });
    // A reply can fail before a publish acknowledgement; avoid unhandled rejection.
    promise.catch(() => {});
    return promise;
  }
  send(frame) { this.socket.send(JSON.stringify(frame)); }
  async publish(event) {
    const accepted = this.wait('Relay publish acknowledgement', (frame) =>
      frame[0] === 'OK' && frame[1] === event.id ? frame[2] : undefined);
    this.send(['EVENT', event]);
    check(await accepted, 'Local relay must acknowledge each published event');
  }
  async nip46(device, method, params) {
    const id = randomUUID();
    const sub = randomUUID();
    const key = getConversationKey(device.secretKey, device.access.bunker_pubkey);
    const request = finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000),
      tags: [['p', device.access.bunker_pubkey]],
      content: encrypt(JSON.stringify({ id, method, params }), key) }, device.secretKey);
    const result = this.wait(`NIP-46 ${method}`, (frame) => {
      if (frame[0] !== 'EVENT' || frame[1] !== sub) return;
      const event = frame[2];
      if (event.pubkey !== device.access.bunker_pubkey || !verifyEvent(event)) return;
      if (!event.tags.some((tag) => tag[0] === 'e' && tag[1] === request.id)) return;
      const response = JSON.parse(decrypt(event.content, key));
      if (response.id === id) return response;
    });
    this.send(['REQ', sub, { kinds: [24133], authors: [device.access.bunker_pubkey], '#p': [device.clientPubkey], since: Math.floor(Date.now() / 1000) - 5 }]);
    await this.publish(request);
    try { return await result; } finally { this.send(['CLOSE', sub]); }
  }
  async readback(event) {
    const sub = randomUUID();
    const found = this.wait('Published group event readback', (frame) => {
      if (frame[0] !== 'EVENT' || frame[1] !== sub) return;
      const stored = frame[2];
      check(verifyEvent(stored), 'Readback event must have a valid BIP-340 signature');
      return stored;
    });
    this.send(['REQ', sub, { ids: [event.id] }]);
    try { assert.deepEqual(await found, event); } finally { this.send(['CLOSE', sub]); }
  }
  async close() {
    this.socket.close();
    await new Promise((resolve) => {
      if (this.socket.readyState === WebSocket.CLOSED) return resolve();
      this.socket.once('close', resolve);
      setTimeout(() => { this.socket.terminate(); resolve(); }, 500).unref();
    });
    sockets.delete(this.socket);
  }
}

async function enroll(admin, group, recovery = false) {
  const secretKey = generateSecretKey();
  const clientPubkey = getPublicKey(secretKey);
  const { body: access } = await api(`/api/groups/${group.id}/${recovery ? 'recover' : 'access'}`, {
    method: 'POST', token: admin.token, data: { client_pubkey: clientPubkey },
  });
  const bunker = new URL(access.bunker_url);
  check(bunker.protocol === 'bunker:' && bunker.hostname === access.bunker_pubkey, 'Enrollment must return its own bunker identity');
  check(bunker.searchParams.getAll('relay').every((url) => url === relayUrl.href || url === relayUrl.href.replace(/\/$/, '')), 'Enrollment relays must match the loopback test relay');
  check(access.group_pubkey === group.pubkey && access.client_pubkey === clientPubkey, 'Enrollment must bind the same group identity to the new client');
  const secret = bunker.searchParams.get('secret');
  check(secret, 'Enrollment must return a one-time bunker secret');
  return { secretKey, clientPubkey, access, secret };
}

async function signAndPublish(device, group, label, published) {
  // Open only this admin's connection. Other admins are entirely offline.
  const relay = await Relay.open();
  try {
    const connected = await relay.nip46(device, 'connect', [device.access.bunker_pubkey, device.secret]);
    check(connected.result === 'ack' && !connected.error, 'An enrolled device must connect with NIP-46');
    const publicKey = await relay.nip46(device, 'get_public_key', []);
    check(publicKey.result === group.pubkey && !publicKey.error, 'NIP-46 must return the original group public key');
    const unsigned = { kind: 1, pubkey: group.pubkey, created_at: Math.floor(Date.now() / 1000), tags: [], content: `Synthetic hosted group demonstration ${label} ${randomUUID()}` };
    const signed = await relay.nip46(device, 'sign_event', [JSON.stringify(unsigned)]);
    check(!signed.error && typeof signed.result === 'string', 'One online admin must independently sign the event');
    const event = JSON.parse(signed.result);
    check(event.pubkey === group.pubkey && verifyEvent(event), 'Independent JavaScript BIP-340 verification must accept the group signature');
    assert.deepEqual(event.tags, unsigned.tags);
    await relay.publish(event);
    const reader = await Relay.open();
    try { await reader.readback(event); } finally { await reader.close(); }
    published.push(event.id);
  } finally { await relay.close(); }
}

async function refused(device) {
  const relay = await Relay.open();
  try {
    for (const [method, params] of [
      ['connect', [device.access.bunker_pubkey, device.secret]],
      ['get_public_key', []],
      ['sign_event', [JSON.stringify({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'Synthetic revoked-device request' })]],
    ]) {
      const result = await relay.nip46(device, method, params);
      check(typeof result.error === 'string' && !result.result, `Revoked device ${method} must receive an explicit denial`);
    }
  } finally { await relay.close(); }
}

async function main() {
  apiUrl = localUrl(process.env.GROUP_DEMO_API_URL, ['http:'], 'GROUP_DEMO_API_URL');
  relayUrl = localUrl(process.env.GROUP_DEMO_RELAY_URL, ['ws:'], 'GROUP_DEMO_RELAY_URL');
  const runId = randomUUID();
  const admins = [];
  for (let index = 0; index < 3; index++) admins.push(await register(index, runId));
  console.log('PASS: three synthetic accounts registered and email verified through HTTP');
  const request = { request_id: runId, name: 'Synthetic hosted demonstration' };
  const { body: group } = await api('/api/groups', { method: 'POST', token: admins[0].token, data: request });
  check(group.mode === 'hosted' && /^[0-9a-f]{64}$/.test(group.pubkey), 'Default group creation must establish one hosted identity');
  const { body: retry } = await api('/api/groups', { method: 'POST', token: admins[0].token, data: request });
  check(retry.id === group.id && retry.pubkey === group.pubkey, 'Creation retry must preserve the group identity');
  for (const admin of admins.slice(1)) {
    await api(`/api/groups/${group.id}/members`, { method: 'POST', token: admins[0].token, data: { admin_pubkey: admin.pubkey } });
    await api(`/api/groups/${group.id}/accept`, { method: 'POST', token: admin.token });
  }
  const devices = [];
  for (const admin of admins) devices.push(await enroll(admin, group));
  check(new Set(devices.map((device) => device.access.authorization_id)).size === 3, 'Each admin/device must have a distinct authorization');
  const published = [];
  for (let index = 0; index < 3; index++) await signAndPublish(devices[index], group, `admin-${index + 1}`, published);
  console.log('PASS: each admin signed alone through encrypted relay NIP-46; all three events independently verified, published and read back');
  await api(`/api/groups/${group.id}/members/${admins[2].pubkey}`, { method: 'DELETE', token: admins[0].token });
  await refused(devices[2]);
  await api(`/api/groups/${group.id}/access`, { method: 'POST', token: admins[2].token, data: { client_pubkey: getPublicKey(generateSecretKey()) }, expected: 403 });
  console.log('PASS: removal denied the warm device connect/get_public_key/sign_event and new enrollment');
  const replacement = await enroll(admins[1], group, true);
  check(replacement.access.authorization_id !== devices[1].access.authorization_id, 'Recovery must issue a fresh authorization');
  check(replacement.access.installation_epoch > devices[1].access.installation_epoch, 'Recovery must advance the installation epoch');
  await signAndPublish(replacement, group, 'replacement-device', published);
  await refused(devices[1]);
  console.log('PASS: replacement device signed as the original identity; all three old-device operations were denied');
  console.log(JSON.stringify({ result: 'passed', synthetic: true, independent_admins: 3, published_and_read_back: published.length, removal_denials: 3, recovery_denials: 3 }));
}

try { await main(); } catch (error) {
  console.error(error instanceof DemoFailure ? `FAIL: ${error.message}` : 'FAIL: unexpected local demonstration error; details suppressed to protect credentials');
  process.exitCode = 1;
} finally {
  for (const socket of sockets) socket.terminate();
}
