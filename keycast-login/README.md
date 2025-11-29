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

// Create client
const client = createKeycastClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'divine',
  redirectUri: window.location.origin + '/callback',
});

// Start OAuth flow
const { url, pkce } = await client.oauth.getAuthorizationUrl();

// Store PKCE verifier for later
sessionStorage.setItem('pkce_verifier', pkce.verifier);

// Redirect to Keycast
window.location.href = url;
```

After the user authorizes, handle the callback:

```typescript
// Parse callback URL
const result = client.oauth.parseCallback(window.location.href);

if ('code' in result) {
  // Exchange code for tokens
  const verifier = sessionStorage.getItem('pkce_verifier');
  const tokens = await client.oauth.exchangeCode(result.code, verifier);

  // tokens.bunker_url - NIP-46 bunker URL for nostr-tools
  // tokens.access_token - UCAN token for REST RPC API
  // tokens.nostr_api - REST RPC API endpoint
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
  nsec: 'nsec1...', // User's existing key
  byokPubkey: 'hex_pubkey',
  defaultRegister: true,
});
```

## API Reference

### KeycastOAuth

- `getAuthorizationUrl(options?)` - Generate OAuth authorization URL
- `exchangeCode(code, verifier?)` - Exchange authorization code for tokens
- `parseCallback(url)` - Parse callback URL for code or error
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
