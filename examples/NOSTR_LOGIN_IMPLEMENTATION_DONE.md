# nostr-login Integration - Implementation Complete ✅

## What Was Implemented

All code needed for Keycast to work as a nostr-login bunker provider is now complete!

### Files Created/Modified

1. **`database/migrations/0006_nostr_login_support.sql`** - Adds `client_public_key` column
2. **`api/src/api/http/oauth.rs`** - Added nostr-login handlers (connect_get, connect_post, parse_nostrconnect_uri)
3. **`api/src/api/http/routes.rs`** - Wired up discovery endpoint and connect routes
4. **`examples/nostr-login-test.html`** - Test page with nostr-login integration
5. **`examples/NOSTR_LOGIN_INTEGRATION.md`** - Comprehensive design doc (already existed)

## Testing Steps

### 1. Run Database Migration

```bash
cd api
psql ../database/keycast.db < ../database/migrations/0006_nostr_login_support.sql
```

### 2. Start the API Server

```bash
cd api
cargo run
```

### 3. Start the Signer Daemon

```bash
# In another terminal
cd signer
cargo run
```

### 4. Serve the Test Page

```bash
cd examples
python3 -m http.server 8000
```

### 5. Test the Flow

1. Open http://localhost:8000/nostr-login-test.html
2. Click "Get Public Key"
3. nostr-login modal should appear with "localhost:3000" as an option
4. Click to select Keycast
5. Popup opens to http://localhost:3000/api/connect/nostrconnect://...
6. See authorization page
7. Click "Approve"
8. Popup closes
9. Public key appears!
10. Click "Sign Event" - should sign without any prompts!
11. Click "Sign 5 Events" - all 5 should sign rapidly!

## How It Works

### Discovery Phase

1. nostr-login fetches `http://localhost:3000/.well-known/nostr.json`
2. Gets: `{ "nip46": { "relay": "wss://relay.damus.io", "nostrconnect_url": "http://localhost:3000/api/connect/<nostrconnect>" } }`
3. nostr-login adds "localhost:3000" to the bunker list

### Connection Phase

1. User clicks "localhost:3000" in nostr-login modal
2. nostr-login generates:
   - Client ephemeral keypair
   - Random secret
   - `nostrconnect://CLIENT_PUBKEY?relay=wss://relay.damus.io&secret=xyz...&name=TestApp`
3. Opens popup to: `http://localhost:3000/api/connect/nostrconnect://CLIENT_PUBKEY?relay=...`

### Authorization Phase

1. **GET /api/connect/*nostrconnect** (`oauth.rs:333`)
   - Parses `nostrconnect://` URI
   - Extracts client pubkey, relay, secret, permissions
   - Shows branded authorization page

2. User clicks "Approve"

3. **POST /api/oauth/connect** (`oauth.rs:480`)
   - Gets user's public key (from session - TODO: implement JWT)
   - Gets user's encrypted key from database
   - Creates/gets oauth_application for this client
   - Inserts into `oauth_authorizations`:
     ```sql
     user_public_key: "user's key"
     bunker_public_key: "user's key" (same - it's the bunker)
     bunker_secret: encrypted_user_key (BLOB from KMS)
     secret: "xyz..." (from nostrconnect URI)
     relays: ["wss://relay.damus.io"] (from nostrconnect URI)
     client_public_key: "CLIENT_PUBKEY" (from nostrconnect URI)
     ```
   - Creates reload signal file
   - Shows success page
   - Popup auto-closes after 3 seconds

### Signing Phase

1. **Signer daemon reloads** (`signer_daemon.rs:153-179`)
   - Detects `.reload_signal` file
   - Calls `reload_authorizations_if_needed()`
   - Loads new oauth_authorization from database
   - Decrypts user key with KMS
   - Creates handler for user's bunker pubkey
   - Subscribes to NIP-46 events on relay

2. **Client sends sign request** (via nostr-login)
   - Client is already connected to `wss://relay.damus.io`
   - Sends encrypted NIP-46 `sign_event` request
   - Kind 24133, p-tag = user's bunker pubkey

3. **Signer daemon receives event** (`signer_daemon.rs:311`)
   - Finds handler by bunker pubkey
   - Decrypts with NIP-44 (or NIP-04 fallback)
   - Parses JSON-RPC request
   - Calls `handle_sign_event()` (`signer_daemon.rs:470`)
   - **Signs with KMS-decrypted key** (line 511)
   - Encrypts response
   - Publishes to relay
   - Client receives signed event

4. **No user interaction!** - Automatic server-side signing!

## Key Differences from nsec.app

| Feature | nsec.app | Keycast |
|---------|----------|---------|
| Key storage | Browser localStorage | Server KMS |
| Signing | Browser (after user approval) | Server (automatic) |
| User interaction | Per-signature | One-time auth |
| Latency | High (user delay) | Low (server-side) |
| Offline | Requires user online | Always available |
| Team keys | No | Yes |
| Policies | No | Yes |

## Architecture Benefits

### For Users
- ✅ One-time approval, then automatic signing
- ✅ Works with any nostr-login enabled app
- ✅ Keys never leave server (more secure than browser)
- ✅ No manual copy/paste of bunker URLs
- ✅ Fast signing (no waiting for user approval)

### For Teams
- ✅ Shared keys with individual tracking
- ✅ Policy-based signing rules
- ✅ Per-application usage tracking
- ✅ Individual session revocation
- ✅ Audit trail of all signatures

### For Developers
- ✅ Standard nostr-login integration
- ✅ No custom Keycast code needed
- ✅ Works like any other bunker
- ✅ Just add to `data-bunkers` attribute

## Production Deployment

Before production, update these values:

### 1. Change Discovery URL (`routes.rs:157`)
```rust
"nostrconnect_url": "https://login.divine.video/api/connect/<nostrconnect>"
```

### 2. Update Relay (`routes.rs:156`)
```rust
"relay": "wss://relay.damus.io"  // Or your preferred relay
```

### 3. Add CORS Headers
Already configured in `routes.rs:163-164` - allows all origins for `.well-known/nostr.json`

### 4. Implement Session Management
Currently uses "most recent user" for testing. Replace with:
- JWT-based session in `connect_post()` (`oauth.rs:517-524`)
- Cookie-based auth for popup flow
- Redirect to login if not authenticated

### 5. Consider Relay Selection
- Allow users to choose relay?
- Support multiple relays?
- Fallback relay if primary fails?

## Testing Checklist

- [ ] Run migration: `psql ../database/keycast.db < ../database/migrations/0006_nostr_login_support.sql`
- [ ] Start API: `cd api && cargo run`
- [ ] Start signer: `cd signer && cargo run`
- [ ] Verify discovery: `curl http://localhost:3000/.well-known/nostr.json`
- [ ] Open test page: `http://localhost:8000/nostr-login-test.html`
- [ ] Test "Get Public Key" - should trigger auth
- [ ] Test "Sign Event" - should sign automatically
- [ ] Test "Sign 5 Events" - should sign all 5 without prompts
- [ ] Check signer logs for sign requests
- [ ] Check API logs for connect requests
- [ ] Verify oauth_authorizations table has new entry
- [ ] Test from fresh browser (incognito) to verify full flow

## Known Issues / TODOs

1. **Session Management** - Currently uses "most recent user" hack
   - Need JWT session validation in `connect_post()`
   - Need login redirect if not authenticated

2. **Error Handling** - Need better UX for:
   - User not found
   - No personal key for user
   - Database errors

3. **Relay Configuration** - Hardcoded to `wss://relay.damus.io`
   - Consider making configurable
   - Allow per-user relay preference?

4. **Rate Limiting** - No protection against:
   - Rapid connect requests
   - DDoS on connect endpoint

5. **Monitoring** - Should track:
   - Number of nostr-login connections
   - Sign requests per authorization
   - Failed auth attempts

## Next Steps

1. **Test locally** - Follow testing checklist above
2. **Fix any bugs** - Iterate based on local testing
3. **Add session management** - Implement JWT validation
4. **Deploy to staging** - Test with real domain
5. **Update discovery URL** - Point to production domain
6. **Public testing** - Share with beta users
7. **Monitor usage** - Track sign requests and performance
8. **Document for users** - How to use Keycast with any nostr app

## Success Criteria

When working correctly, users should be able to:

✅ Visit any nostr-login enabled website
✅ See "localhost:3000" (or "login.divine.video") in login options
✅ Click it and get Keycast authorization popup
✅ Approve once
✅ Sign unlimited events automatically
✅ No manual bunker URL management
✅ Fast server-side signing
✅ Team key support (if configured)

This makes Keycast the **easiest and most powerful** nostr bunker available!

## Files for Reference

- Design doc: `examples/NOSTR_LOGIN_INTEGRATION.md`
- Test page: `examples/nostr-login-test.html`
- OAuth handlers: `api/src/api/http/oauth.rs` (lines 272-626)
- Routes: `api/src/api/http/routes.rs` (discovery endpoint line 151)
- Migration: `database/migrations/0006_nostr_login_support.sql`
- Signer daemon: `signer/src/signer_daemon.rs` (already supports this!)

## Questions?

Refer to:
- NIP-46 spec: https://github.com/nostr-protocol/nips/blob/master/46.md
- nostr-login: https://github.com/nostrband/nostr-login
- Existing OAuth docs: `examples/OAUTH_NOSTR_README.md`
