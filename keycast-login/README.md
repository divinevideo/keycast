# keycast-login

Drop-in Nostr authentication library with Keycast server-side signing and multiple provider support.

## Features

- 🔑 **Keycast Provider** - Default server-based authentication with KMS-backed signing
- 🦊 **NIP-07 Provider** - Browser extension support (Alby, nos2x, etc.)
- 🔗 **Bunker URL Provider** - Bring your own NIP-46 bunker
- 🎨 **Customizable UI** - Built-in modal or headless mode
- ⚡ **Auto-detection** - Automatically defaults to same-domain Keycast instance
- 🔒 **Zero keys in browser** - Server-side signing with policy enforcement

## Installation

```bash
npm install keycast-login nostr-tools
```

## Quick Start

```html
<script type="module">
  import KeycastLogin from 'keycast-login';

  const auth = new KeycastLogin({
    // Auto-detects provider at current domain
    // e.g., running on divine.video uses login.divine.video
    defaultProvider: 'auto',

    // Or specify custom provider
    // defaultProvider: 'https://login.divine.video',

    // Enable fallback providers
    enableNip07: true,
    enableBunkerUrl: true
  });

  // Get user's public key
  const pubkey = await auth.getPublicKey();

  // Sign an event
  const event = {
    kind: 1,
    content: 'Hello Nostr!',
    tags: [],
    created_at: Math.floor(Date.now() / 1000)
  };

  const signedEvent = await auth.signEvent(event);
</script>
```

## Usage

### Default Keycast Auth (Golden Path)

```javascript
const auth = new KeycastLogin();

// Shows modal with Keycast auth form
// If user doesn't exist, creates account
// If user exists, logs them in
const pubkey = await auth.getPublicKey();
```

### With Provider Options

```javascript
const auth = new KeycastLogin({
  keycast: {
    mode: 'auto',  // Auto-detect from domain
    knownProviders: [
      { domain: 'login.divine.video', name: 'Divine' },
      { domain: 'auth.protest.net', name: 'Protest' }
    ],
    allowCustom: true
  },
  enableNip07: true,
  enableCustomBunker: true
});

// Modal shows:
// 1. Primary: "Sign in to [detected domain]" form
// 2. Link: "or sign in with:"
//    - Different Keycast server (shows list)
//    - Browser extension (NIP-07)
//    - Custom bunker URL
```

### Headless Mode

```javascript
const auth = new KeycastLogin({ headless: true });

// Handle auth yourself
auth.on('auth-required', async () => {
  // Show your own UI
  const email = await promptForEmail();
  const password = await promptForPassword();

  await auth.authenticate({ email, password });
});

const pubkey = await auth.getPublicKey();
```

## Configuration

```javascript
new KeycastLogin({
  // Keycast provider settings
  keycast: {
    mode: 'auto' | 'select' | 'custom',
    defaultDomain: string,
    knownProviders: [
      { domain: string, name: string, description?: string }
    ],
    allowCustom: boolean
  },

  // Alternative auth methods
  enableNip07: boolean,
  enableCustomBunker: boolean,

  // UI settings
  headless: boolean,
  theme: 'dark' | 'light',
  brandColor: string,

  // Behavior
  autoConnect: boolean,
  rememberChoice: boolean,
  cacheTimeout: number
});
```

## API

### Methods

- `getPublicKey(): Promise<string>` - Get authenticated user's public key
- `signEvent(event): Promise<SignedEvent>` - Sign a Nostr event
- `nip04Encrypt(pubkey, plaintext): Promise<string>` - NIP-04 encryption
- `nip04Decrypt(pubkey, ciphertext): Promise<string>` - NIP-04 decryption
- `nip44Encrypt(pubkey, plaintext): Promise<string>` - NIP-44 encryption
- `nip44Decrypt(pubkey, ciphertext): Promise<string>` - NIP-44 decryption
- `disconnect()` - Clear session and disconnect
- `getProvider(): string` - Get current provider name

### Events

```javascript
auth.on('connected', (pubkey) => {});
auth.on('disconnected', () => {});
auth.on('error', (error) => {});
auth.on('provider-changed', (provider) => {});
```

## Architecture

### Keycast Provider Flow

1. User enters email/password in modal
2. Try register → if exists, try login
3. Server creates/retrieves KMS-encrypted key
4. Returns JWT token
5. Get bunker URL from API
6. Connect via NIP-46 to signer daemon
7. All signing happens server-side with zero user prompts

### Provider Priority

1. **Keycast (Default)** - Server-based auth at same domain
2. **NIP-07** - Browser extension if available
3. **Bunker URL** - User provides their own
4. **Other Keycast** - List of known instances

## Comparison

| Feature | Keycast | nsec.app | Extension |
|---------|---------|----------|-----------|
| Key storage | Server KMS | Browser | Browser |
| Signing | Server-side | Push notification | Extension popup |
| Always available | ✅ | ❌ | ❌ |
| Zero prompts | ✅ | ❌ | ❌ |
| Team keys | ✅ | ❌ | ❌ |
| Policy enforcement | ✅ | ❌ | ❌ |

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev
```

## License

MIT
