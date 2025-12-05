# keycast-login

TypeScript client for Keycast OAuth authentication and Nostr signing via REST RPC.

## Installation

```bash
npm install keycast-login
# or
bun add keycast-login
```

## Quick Start

```typescript
import { createKeycastClient } from 'keycast-login';

// Create client with optional storage for automatic credential management
const client = createKeycastClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'divine',
  redirectUri: window.location.origin + '/callback',
  storage: localStorage, // Optional: auto-saves credentials (defaults to in-memory)
});

// Check for existing session
const existingSession = client.oauth.getSession();
if (existingSession) {
  // User is already authenticated
  const rpc = client.createRpc({ access_token: existingSession.accessToken, bunker_url: existingSession.bunkerUrl });
}

// Start OAuth flow (auto-includes authorization_handle for silent re-auth)
const { url, pkce } = await client.oauth.getAuthorizationUrl();

// Store PKCE verifier for callback (library stores internally but redirect loses state)
sessionStorage.setItem('pkce_verifier', pkce.verifier);

// Redirect to Keycast
window.location.href = url;
```

After the user authorizes, handle the callback:

```typescript
// Parse callback URL
const result = client.oauth.parseCallback(window.location.href);

if ('code' in result) {
  // Exchange code for tokens (auto-saves to storage)
  const verifier = sessionStorage.getItem('pkce_verifier');
  const tokens = await client.oauth.exchangeCode(result.code, verifier);

  // tokens.bunker_url - NIP-46 bunker URL for nostr-tools
  // tokens.access_token - UCAN token for REST RPC API
  // tokens.authorization_handle - Handle for silent re-auth
}
```

## REST RPC API (Low-Latency)

The REST RPC API provides a low-latency alternative to NIP-46 relay-based signing:

```typescript
import { KeycastRpc } from 'keycast-login';

const rpc = new KeycastRpc({
  nostrApi: tokens.nostr_api,
  accessToken: tokens.access_token,
});

// Get public key
const pubkey = await rpc.getPublicKey();

// Sign an event
const signed = await rpc.signEvent({
  kind: 1,
  content: 'Hello, Nostr!',
  tags: [],
  created_at: Math.floor(Date.now() / 1000),
  pubkey: pubkey,
});

// NIP-44 encryption/decryption
const ciphertext = await rpc.nip44Encrypt(recipientPubkey, 'secret message');
const plaintext = await rpc.nip44Decrypt(senderPubkey, ciphertext);

// NIP-04 encryption/decryption (legacy)
const encrypted = await rpc.nip04Encrypt(recipientPubkey, 'secret message');
const decrypted = await rpc.nip04Decrypt(senderPubkey, encrypted);
```

## BYOK (Bring Your Own Key)

Import an existing Nostr identity during OAuth:

```typescript
const { url, pkce } = await client.oauth.getAuthorizationUrl({
  nsec: 'nsec1...', // User's existing key (pubkey derived automatically)
  defaultRegister: true,
});
```

## Storage Interface

The library accepts any storage backend compatible with the `KeycastStorage` interface:

```typescript
interface KeycastStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
```

Built-in options:
- `localStorage` - Persists across browser sessions
- `sessionStorage` - Cleared when tab closes
- In-memory (default) - No persistence

Storage keys used:
- `keycast_session` - Full session credentials
- `keycast_auth_handle` - Authorization handle (for silent re-auth when session expires)

## API Reference

### KeycastOAuth

**OAuth Flow:**
- `getAuthorizationUrl(options?)` - Generate OAuth authorization URL (auto-includes stored handle)
- `exchangeCode(code, verifier?)` - Exchange authorization code for tokens (auto-saves to storage)
- `parseCallback(url)` - Parse callback URL for code or error

**Storage Management:**
- `getSession()` - Get stored session (returns null if expired or missing)
- `getAuthorizationHandle()` - Get stored authorization handle for silent re-auth
- `logout()` - Clear all session data including authorization handle (use when user explicitly logs out)

**Utilities:**
- `toStoredCredentials(response)` - Convert token response to storable format
- `isExpired(credentials)` - Check if credentials are expired

### KeycastRpc

- `getPublicKey()` - Get user's public key (hex)
- `signEvent(event)` - Sign an unsigned Nostr event
- `nip44Encrypt(pubkey, plaintext)` - Encrypt with NIP-44
- `nip44Decrypt(pubkey, ciphertext)` - Decrypt with NIP-44
- `nip04Encrypt(pubkey, plaintext)` - Encrypt with NIP-04 (legacy)
- `nip04Decrypt(pubkey, ciphertext)` - Decrypt with NIP-04 (legacy)

### Utilities

- `generatePkce(nsec?)` - Generate PKCE challenge/verifier pair
- `validatePkce(verifier, challenge, method?)` - Validate PKCE challenge

## License

MIT
