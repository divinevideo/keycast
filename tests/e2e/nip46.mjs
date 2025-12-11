#!/usr/bin/env node

import { SimplePool, getPublicKey, generateSecretKey, finalizeEvent, nip44, nip19 } from 'nostr-tools';

const API_URL = "https://login.divine.video";
const EMAIL = `test-${Date.now()}@example.com`;
const PASSWORD = "testpassword123";

console.log("==========================================");
console.log("🧪 Complete NIP-46 End-to-End Test");
console.log("==========================================");
console.log(`API: ${API_URL}`);
console.log(`Email: ${EMAIL}`);
console.log("");

let bunkerPubkey, relayUrl, secret, localSk, conversationKey, pool;
let requestId = 0;
const pendingRequests = {};

function parseBunkerUrl(url) {
    const match = url.match(/bunker:\/\/([0-9a-f]+)\?relay=([^&]+)&secret=([^&]+)/);
    if (!match) throw new Error('Invalid bunker URL');
    return { pubkey: match[1], relay: decodeURIComponent(match[2]), secret: match[3] };
}

async function sendRequest(method, params) {
    return new Promise(async (resolve, reject) => {
        const id = `req-${++requestId}`;
        const request = { id, method, params };

        console.log(`  📤 Sending ${method} request (id: ${id})`);

        // Encrypt
        const encrypted = nip44.encrypt(JSON.stringify(request), conversationKey);

        // Build event
        const event = {
            kind: 24133,
            created_at: Math.floor(Date.now() / 1000),
            tags: [['p', bunkerPubkey]],
            content: encrypted
        };

        const signedEvent = finalizeEvent(event, localSk);

        // Store pending request
        pendingRequests[id] = { resolve, reject, method, timestamp: Date.now() };

        // Add timeout
        setTimeout(() => {
            if (pendingRequests[id]) {
                delete pendingRequests[id];
                reject(new Error(`Timeout waiting for ${method} response`));
            }
        }, 30000); // 30 second timeout

        // Publish
        await pool.publish([relayUrl], signedEvent);
        console.log(`  ✅ Published ${method} request to relay`);
    });
}

async function main() {
    try {
        // Step 1: Register
        console.log("📝 Step 1: Registering user...");
        const registerResp = await fetch(`${API_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: EMAIL, password: PASSWORD })
        });

        const registerData = await registerResp.json();
        if (!registerResp.ok) throw new Error(registerData.error || 'Registration failed');

        const ucanToken = registerData.token;
        console.log(`✅ Registered: ${registerData.pubkey.substring(0, 16)}...`);
        console.log("");

        // Step 2: OAuth Approve
        console.log("🔐 Step 2: OAuth authorization...");
        const approveResp = await fetch(`${API_URL}/api/oauth/authorize`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${ucanToken}`
            },
            body: JSON.stringify({
                client_id: 'test-nip46-client',
                redirect_uri: 'http://localhost:8000/callback',
                scope: 'sign_event',
                approved: true
            })
        });

        const approveData = await approveResp.json();
        if (!approveResp.ok) throw new Error(approveData.error || 'OAuth failed');

        const authCode = approveData.code;
        console.log(`✅ Got authorization code: ${authCode.substring(0, 20)}...`);
        console.log("");

        // Step 3: Exchange for bunker URL
        console.log("🔑 Step 3: Exchanging code for bunker URL...");
        const tokenResp = await fetch(`${API_URL}/api/oauth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                code: authCode,
                client_id: 'test-nip46-client',
                redirect_uri: 'http://localhost:8000/callback'
            })
        });

        const tokenData = await tokenResp.json();
        if (!tokenResp.ok) throw new Error(tokenData.error || 'Token exchange failed');

        const bunkerUrl = tokenData.bunker_url;
        console.log(`✅ Got bunker URL: ${bunkerUrl}`);

        const parsed = parseBunkerUrl(bunkerUrl);
        bunkerPubkey = parsed.pubkey;
        relayUrl = parsed.relay;
        secret = parsed.secret;

        console.log(`  Bunker Pubkey: ${bunkerPubkey}`);
        console.log(`  Relay: ${relayUrl}`);
        console.log(`  Secret: ${secret.substring(0, 10)}...`);
        console.log("");

        // Step 4: Wait for signer to reload
        console.log("⏳ Step 4: Waiting 3 seconds for signer to load authorization...");
        await new Promise(resolve => setTimeout(resolve, 3000));
        console.log("");

        // Step 5: Generate local keypair
        console.log("🔐 Step 5: Generating local keypair...");
        localSk = generateSecretKey();
        const localPk = getPublicKey(localSk);
        console.log(`✅ Local pubkey: ${localPk}`);

        // Calculate conversation key
        conversationKey = nip44.getConversationKey(localSk, bunkerPubkey);
        console.log("✅ Conversation key calculated");
        console.log("");

        // Step 6: Connect to relay
        console.log("🔌 Step 6: Connecting to relay...");
        pool = new SimplePool();
        await pool.ensureRelay(relayUrl);
        console.log(`✅ Connected to ${relayUrl}`);
        console.log("");

        // Step 7: Subscribe to responses
        console.log("📡 Step 7: Subscribing to NIP-46 responses...");
        const filter = {
            kinds: [24133],
            authors: [bunkerPubkey],
            '#p': [localPk],
            since: Math.floor(Date.now() / 1000) - 10
        };

        pool.subscribeMany([relayUrl], [filter], {
            onevent(event) {
                console.log(`  📥 Received event from signer: ${event.id.substring(0, 16)}...`);
                try {
                    const decrypted = nip44.decrypt(event.content, conversationKey);
                    const response = JSON.parse(decrypted);
                    console.log(`  📦 Decrypted response:`, response);

                    const { id, result, error } = response;
                    const pending = pendingRequests[id];

                    if (pending) {
                        console.log(`  ✅ Matched pending ${pending.method} request (${Date.now() - pending.timestamp}ms)`);
                        if (error) {
                            pending.reject(new Error(error));
                        } else {
                            pending.resolve(result);
                        }
                        delete pendingRequests[id];
                    } else {
                        console.log(`  ⚠️  No pending request found for ID: ${id}`);
                    }
                } catch (e) {
                    console.error(`  ❌ Decrypt failed:`, e.message);
                }
            }
        });

        console.log("✅ Subscribed to responses");
        console.log("");

        // Step 8: Send connect request
        console.log("🤝 Step 8: Sending NIP-46 connect request...");
        const connectResult = await sendRequest('connect', [bunkerPubkey, secret]);
        console.log(`✅ Connect result: ${connectResult}`);

        if (connectResult !== 'ack') {
            throw new Error(`Expected 'ack', got: ${connectResult}`);
        }
        console.log("");

        // Step 9: Get public key
        console.log("🔑 Step 9: Getting user public key...");
        const userPubkey = await sendRequest('get_public_key', []);
        const userNpub = nip19.npubEncode(userPubkey);
        console.log(`✅ User pubkey (hex): ${userPubkey}`);
        console.log(`✅ User pubkey (npub): ${userNpub}`);
        console.log(`🔗 View profile: https://njump.me/${userNpub}`);
        console.log("");

        // Step 10: Sign event
        console.log("✍️  Step 10: Signing test event...");
        const unsignedEvent = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: "Hello from complete NIP-46 E2E test! 🎉"
        };

        const signedEventStr = await sendRequest('sign_event', [JSON.stringify(unsignedEvent)]);
        const signedEvent = JSON.parse(signedEventStr);

        const nevent = nip19.neventEncode({ id: signedEvent.id, author: signedEvent.pubkey });
        const note = nip19.noteEncode(signedEvent.id);

        console.log(`✅ Event signed!`);
        console.log(`  Event ID (hex): ${signedEvent.id}`);
        console.log(`  Event ID (note): ${note}`);
        console.log(`  Event ID (nevent): ${nevent}`);
        console.log(`  Signature: ${signedEvent.sig.substring(0, 32)}...`);
        console.log(`  Content: ${signedEvent.content}`);
        console.log(`  🔗 View event: https://njump.me/${nevent}`);
        console.log("");

        console.log("==========================================");
        console.log("✅ COMPLETE END-TO-END TEST PASSED!");
        console.log("==========================================");
        console.log("");
        console.log("Summary:");
        console.log("  ✅ OAuth registration");
        console.log("  ✅ Bunker URL generation");
        console.log("  ✅ Signer loaded authorization");
        console.log("  ✅ NIP-46 connect");
        console.log("  ✅ NIP-46 get_public_key");
        console.log("  ✅ NIP-46 sign_event");
        console.log("");
        console.log("🎉 The signer is receiving payloads from the relay and responding!");

        pool.close([relayUrl]);
        process.exit(0);

    } catch (error) {
        console.error("");
        console.error("==========================================");
        console.error("❌ TEST FAILED");
        console.error("==========================================");
        console.error(error);

        if (pool) {
            pool.close([relayUrl]);
        }
        process.exit(1);
    }
}

main();
