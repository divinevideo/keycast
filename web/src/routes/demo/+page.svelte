<script lang="ts">
  import { onMount } from "svelte";
  import { browser } from "$app/environment";
  import { page } from "$app/stores";
  import DemoSection from "$lib/components/demo/DemoSection.svelte";
  import ResultDisplay from "$lib/components/demo/ResultDisplay.svelte";
  import Copy from "$lib/components/Copy.svelte";
  import {
    Key,
    Lightning,
    Lock,
    LockOpen,
    ArrowRight,
    Plugs,
    Code,
  } from "phosphor-svelte";

  // Import keycast-login library
  import { createKeycastClient, KeycastRpc, generatePkce } from "keycast-login";

  // Configuration
  const SERVER_URL = import.meta.env.VITE_DOMAIN || "http://localhost:3000";
  const CLIENT_ID = "diVine Login Demo";
  console.log(
    "SERVER_URL:",
    SERVER_URL,
    "VITE_DOMAIN:",
    import.meta.env.VITE_DOMAIN,
  );

  // Create Keycast client (initialized in onMount for SSR safety)
  let client: ReturnType<typeof createKeycastClient> | null = null;
  let rpc: KeycastRpc | null = null;

  // State
  type Status = "idle" | "loading" | "success" | "error";

  let identity: { nsec: string; npub: string; pubkey: string } | null =
    $state(null);
  let credentials: {
    bunkerUrl: string;
    accessToken: string;
    nostrApi: string;
    authorizationHandle?: string;
  } | null = $state(null);
  let connected = $derived(credentials !== null);

  // OAuth state
  let oauthStatus: Status = $state("idle");
  let oauthError: string | null = $state(null);

  // RPC states
  let pubkeyStatus: Status = $state("idle");
  let pubkeyResult: string | null = $state(null);
  let pubkeyError: string | null = $state(null);

  let signStatus: Status = $state("idle");
  let signResult: object | null = $state(null);
  let signError: string | null = $state(null);
  let signContent = $state("Hello from Keycast demo!");

  // Encrypt/Decrypt states for NIP-44
  let encryptMethod: "nip44" | "nip04" = $state("nip44");
  let encryptPubkey = $state("");
  let encryptInput = $state("Secret message");
  let encryptStatus: Status = $state("idle");
  let encryptResult: string | null = $state(null);
  let encryptError: string | null = $state(null);

  let decryptInput = $state("");
  let decryptStatus: Status = $state("idle");
  let decryptResult: string | null = $state(null);
  let decryptError: string | null = $state(null);

  // Initialize Keycast client (must be called in browser)
  function initClient() {
    if (!browser || client) return;

    const redirectUri = window.location.origin + window.location.pathname;
    client = createKeycastClient({
      serverUrl: SERVER_URL,
      clientId: CLIENT_ID,
      redirectUri,
    });
  }

  // Generate test identity using nostr-tools
  async function generateIdentity() {
    if (!browser) return;

    const { generateSecretKey, getPublicKey } = await import(
      "nostr-tools/pure"
    );
    const { nsecEncode, npubEncode } = await import("nostr-tools/nip19");

    const sk = generateSecretKey();
    const pk = getPublicKey(sk);

    identity = {
      nsec: nsecEncode(sk),
      npub: npubEncode(pk),
      pubkey: pk,
    };

    sessionStorage.setItem("demo_identity", JSON.stringify(identity));
  }

  // OAuth: Connect with server-generated key
  async function connectWithKeycast() {
    initClient();
    if (!client) return;

    oauthStatus = "loading";
    oauthError = null;

    try {
      const { url, pkce } = await client.oauth.getAuthorizationUrl({
        scopes: ["policy:social"],
        defaultRegister: true,
        authorizationHandle: credentials?.authorizationHandle,
      });

      console.log("OAuth URL:", url); // Debug
      sessionStorage.setItem("pkce_verifier", pkce.verifier);
      sessionStorage.setItem("byok_used", "false");

      window.location.href = url;
    } catch (e) {
      oauthStatus = "error";
      oauthError = e instanceof Error ? e.message : "OAuth error";
    }
  }

  // OAuth: Connect with existing key (BYOK)
  async function connectWithBYOK() {
    initClient();
    if (!client) return;

    if (!identity) {
      oauthError = "Generate an identity first";
      return;
    }

    oauthStatus = "loading";
    oauthError = null;

    try {
      // Pubkey is derived automatically from nsec inside the library
      const { url, pkce } = await client.oauth.getAuthorizationUrl({
        scopes: ["policy:social"],
        defaultRegister: true,
        nsec: identity.nsec,
      });

      sessionStorage.setItem("pkce_verifier", pkce.verifier);
      sessionStorage.setItem("byok_used", "true");
      sessionStorage.setItem("byok_pubkey", identity.pubkey);

      window.location.href = url;
    } catch (e) {
      oauthStatus = "error";
      oauthError = e instanceof Error ? e.message : "OAuth error";
    }
  }

  // Exchange authorization code for tokens
  async function exchangeCode(code: string) {
    initClient();
    if (!client) return;

    oauthStatus = "loading";

    try {
      const verifier = sessionStorage.getItem("pkce_verifier");
      if (!verifier) throw new Error("Missing PKCE verifier");

      const tokens = await client.oauth.exchangeCode(code, verifier);

      credentials = {
        bunkerUrl: tokens.bunker_url,
        accessToken: tokens.access_token ?? "",
        nostrApi: `${SERVER_URL}/api/nostr`,
        authorizationHandle: tokens.authorization_handle,
      };

      // Create RPC client from tokens
      rpc = client.createRpc(tokens);

      // Store credentials
      localStorage.setItem("demo_credentials", JSON.stringify(credentials));

      oauthStatus = "success";

      // Clean URL
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (e) {
      oauthStatus = "error";
      oauthError = e instanceof Error ? e.message : "Token exchange failed";
    }
  }

  // Initialize RPC client from stored credentials
  function initRpc() {
    if (rpc || !credentials?.accessToken) return;

    rpc = new KeycastRpc({
      nostrApi: credentials.nostrApi,
      accessToken: credentials.accessToken,
    });
  }

  // RPC: Get public key
  async function rpcGetPublicKey() {
    initRpc();
    if (!rpc) {
      pubkeyError = "Not connected";
      pubkeyStatus = "error";
      return;
    }

    pubkeyStatus = "loading";
    pubkeyResult = null;
    pubkeyError = null;

    try {
      const result = await rpc.getPublicKey();
      pubkeyResult = result;
      pubkeyStatus = "success";

      // Auto-populate encrypt pubkey only if empty
      if (!encryptPubkey) {
        encryptPubkey = result;
      }
    } catch (e) {
      pubkeyStatus = "error";
      pubkeyError = e instanceof Error ? e.message : "RPC error";
    }
  }

  // RPC: Sign event
  async function rpcSignEvent() {
    initRpc();
    if (!rpc) {
      signError = "Not connected";
      signStatus = "error";
      return;
    }

    signStatus = "loading";
    signResult = null;
    signError = null;

    try {
      const unsignedEvent = {
        kind: 1,
        content: signContent,
        tags: [],
        created_at: Math.floor(Date.now() / 1000),
        pubkey:
          pubkeyResult ||
          "0000000000000000000000000000000000000000000000000000000000000000",
      };

      const result = await rpc.signEvent(unsignedEvent);
      signResult = result;
      signStatus = "success";
    } catch (e) {
      signStatus = "error";
      signError = e instanceof Error ? e.message : "Signing failed";
    }
  }

  // RPC: Encrypt
  async function rpcEncrypt() {
    initRpc();
    if (!rpc) {
      encryptError = "Not connected";
      encryptStatus = "error";
      return;
    }

    if (!encryptPubkey) {
      encryptError = "Enter a recipient pubkey";
      encryptStatus = "error";
      return;
    }

    encryptStatus = "loading";
    encryptResult = null;
    encryptError = null;

    try {
      const result =
        encryptMethod === "nip44"
          ? await rpc.nip44Encrypt(encryptPubkey, encryptInput)
          : await rpc.nip04Encrypt(encryptPubkey, encryptInput);
      encryptResult = result;
      encryptStatus = "success";
    } catch (e) {
      encryptStatus = "error";
      encryptError = e instanceof Error ? e.message : "Encryption failed";
    }
  }

  // RPC: Decrypt
  async function rpcDecrypt() {
    initRpc();
    if (!rpc) {
      decryptError = "Not connected";
      decryptStatus = "error";
      return;
    }

    if (!encryptPubkey) {
      decryptError = "Enter the sender pubkey";
      decryptStatus = "error";
      return;
    }

    decryptStatus = "loading";
    decryptResult = null;
    decryptError = null;

    try {
      const result =
        encryptMethod === "nip44"
          ? await rpc.nip44Decrypt(encryptPubkey, decryptInput)
          : await rpc.nip04Decrypt(encryptPubkey, decryptInput);
      decryptResult = result;
      decryptStatus = "success";
    } catch (e) {
      decryptStatus = "error";
      decryptError = e instanceof Error ? e.message : "Decryption failed";
    }
  }

  // Use encrypted result as decrypt input
  function useAsDecryptInput() {
    if (encryptResult) {
      decryptInput = encryptResult;
    }
  }

  // Clear everything and sign out
  async function disconnect() {
    // Clear all localStorage/sessionStorage
    localStorage.removeItem("demo_credentials");
    sessionStorage.removeItem("pkce_verifier");
    sessionStorage.removeItem("byok_used");
    sessionStorage.removeItem("byok_pubkey");
    sessionStorage.removeItem("demo_identity");

    // Clear keycast_session cookie via logout endpoint (HttpOnly cookies can't be cleared via JS)
    try {
      await fetch(`${SERVER_URL}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (e) {
      console.warn("Logout request failed:", e);
    }

    // Reload page to show fresh state
    window.location.reload();
  }

  // Initialize on mount
  onMount(async () => {
    // Load stored identity
    const storedIdentity = sessionStorage.getItem("demo_identity");
    if (storedIdentity) {
      identity = JSON.parse(storedIdentity);
    } else {
      await generateIdentity();
    }

    // Load stored credentials
    const storedCredentials = localStorage.getItem("demo_credentials");
    if (storedCredentials) {
      credentials = JSON.parse(storedCredentials);
      oauthStatus = "success";
      // Don't auto-fetch - let user click the button
    }

    // Check for OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const error = urlParams.get("error");

    if (error) {
      oauthStatus = "error";
      oauthError = urlParams.get("error_description") || error;
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (code) {
      await exchangeCode(code);
    }
  });
</script>

<svelte:head>
  <title>Integration Demo - Keycast</title>
</svelte:head>

<div class="max-w-3xl mx-auto py-8">
  <!-- Header -->
  <header class="mb-8">
    <h1 class="text-3xl font-bold font-heading flex items-center gap-3">
      <Plugs size={32} weight="duotone" class="text-divine-green" />
      Integration Demo
    </h1>
    <p class="mt-2" style="color: var(--color-divine-text-secondary);">
      Test Keycast OAuth and REST signing APIs.
      <a href="/docs" class="text-link">View API documentation</a>
    </p>
  </header>

  <!-- Step 1: Connect -->
  <DemoSection
    title="1. Connect"
    description="Authenticate with Keycast to get signing credentials"
    tooltip="OAuth 2.0 with PKCE security"
  >
    {#if connected}
      <div class="connected-banner">
        <span class="connected-text">Connected</span>
        <button class="btn btn-secondary" onclick={disconnect}>
          Disconnect
        </button>
      </div>

      <p class="hint-text">
        To test the OAuth approval flow again, first <a
          href="/"
          class="text-link">revoke the "diVine Login Demo" authorization</a
        > in your dashboard, then click Disconnect above.
      </p>

      {#if credentials?.bunkerUrl}
        <div class="credential-display">
          <label>Bunker URL</label>
          <div class="credential-value">
            <code>{credentials.bunkerUrl.substring(0, 60)}...</code>
            <Copy value={credentials.bunkerUrl} size="16" />
          </div>
        </div>
      {/if}
    {:else}
      <div class="connect-options">
        <div class="connect-option">
          <h3>
            <Key size={20} weight="duotone" />
            New Registration
          </h3>
          <p>Keycast will generate a new Nostr identity for you.</p>
          <button
            class="btn btn-primary"
            onclick={connectWithKeycast}
            disabled={oauthStatus === "loading"}
          >
            {oauthStatus === "loading"
              ? "Connecting..."
              : "Connect with Keycast"}
          </button>
        </div>

        <div class="divider">or</div>

        <div class="connect-option">
          <h3>
            <Lock size={20} weight="duotone" />
            Bring Your Own Key
          </h3>
          <p>
            Use an existing Nostr identity. Your key is securely transferred via
            PKCE.
          </p>

          {#if identity}
            <div class="identity-display">
              <div class="identity-row">
                <span class="identity-label">npub</span>
                <code>{identity.npub.substring(0, 20)}...</code>
                <Copy value={identity.npub} size="14" />
              </div>
            </div>
            <div class="button-group">
              <button
                class="btn btn-primary"
                onclick={connectWithBYOK}
                disabled={oauthStatus === "loading"}
              >
                {oauthStatus === "loading"
                  ? "Connecting..."
                  : "Connect with This Key"}
              </button>
              <button class="btn btn-secondary" onclick={generateIdentity}>
                Generate New
              </button>
            </div>
          {/if}
        </div>
      </div>

      {#if oauthStatus === "error" && oauthError}
        <div class="error-banner">{oauthError}</div>
      {/if}
    {/if}
  </DemoSection>

  <!-- Step 2: Sign Events (only shown when connected) -->
  {#if connected}
    <DemoSection
      title="2. Sign Events"
      description="Sign Nostr events using the REST RPC API"
      tooltip="Low-latency signing without relays"
    >
      <div class="action-group">
        <button class="btn btn-primary" onclick={rpcGetPublicKey}>
          <Lightning size={16} weight="fill" />
          Get Public Key
        </button>
        <ResultDisplay
          status={pubkeyStatus}
          result={pubkeyResult}
          error={pubkeyError}
          label="Public Key"
        />
      </div>

      <div class="action-group">
        <div class="form-group">
          <label for="sign-content">Event Content</label>
          <textarea
            id="sign-content"
            bind:value={signContent}
            rows="2"
            placeholder="Enter your message..."
          ></textarea>
        </div>
        <button class="btn btn-primary" onclick={rpcSignEvent}>
          <Lightning size={16} weight="fill" />
          Sign Event
        </button>
        <ResultDisplay
          status={signStatus}
          result={signResult}
          error={signError}
          label="Signed Event"
        />
      </div>
    </DemoSection>

    <!-- Step 3: Encrypt/Decrypt -->
    <DemoSection
      title="3. Encrypt / Decrypt"
      description="NIP-44 (modern) and NIP-04 (legacy) encryption"
      tooltip="Choose encryption method for private messages"
    >
      <!-- Method selector -->
      <div class="method-selector">
        <button
          class="method-btn"
          class:active={encryptMethod === "nip44"}
          onclick={() => (encryptMethod = "nip44")}
        >
          NIP-44 (Modern)
        </button>
        <button
          class="method-btn"
          class:active={encryptMethod === "nip04"}
          onclick={() => (encryptMethod = "nip04")}
        >
          NIP-04 (Legacy)
        </button>
      </div>

      <div class="form-group">
        <label for="encrypt-pubkey">Recipient/Sender Pubkey (hex)</label>
        <input
          id="encrypt-pubkey"
          type="text"
          bind:value={encryptPubkey}
          placeholder="Auto-filled with your key for testing"
        />
      </div>

      <!-- Encrypt/Decrypt Row -->
      <div class="encrypt-decrypt-row">
        <div class="action-group flex-1">
          <label for="encrypt-input" class="form-label">Plaintext</label>
          <textarea
            id="encrypt-input"
            bind:value={encryptInput}
            rows="2"
            placeholder="Enter message to encrypt..."
          ></textarea>
          <button class="btn btn-primary" onclick={rpcEncrypt}>
            <Lock size={16} weight="fill" />
            Encrypt
          </button>
          <ResultDisplay
            status={encryptStatus}
            result={encryptResult}
            error={encryptError}
            label="Ciphertext"
          />
          {#if encryptStatus === "success" && encryptResult}
            <button
              class="btn btn-sm btn-ghost mt-2"
              onclick={useAsDecryptInput}
            >
              <ArrowRight size={14} />
              Use as decrypt input
            </button>
          {/if}
        </div>

        <div class="action-group flex-1">
          <label for="decrypt-input" class="form-label">Ciphertext</label>
          <textarea
            id="decrypt-input"
            bind:value={decryptInput}
            rows="2"
            placeholder="Paste ciphertext to decrypt..."
          ></textarea>
          <button class="btn btn-primary" onclick={rpcDecrypt}>
            <LockOpen size={16} weight="fill" />
            Decrypt
          </button>
          <ResultDisplay
            status={decryptStatus}
            result={decryptResult}
            error={decryptError}
            label="Plaintext"
          />
        </div>
      </div>
    </DemoSection>

    <!-- Code Examples -->
    <DemoSection
      title="Code Examples"
      description="Using keycast-login library"
    >
      <div class="code-example">
        <div class="code-header">
          <Code size={16} />
          <span>1. Setup OAuth Client</span>
        </div>
        <pre><code
            >import {"{"} createKeycastClient {"}"} from 'keycast-login';

const client = createKeycastClient({"{"}
  serverUrl: 'https://login.divine.video',
  clientId: 'your-app',
  redirectUri: window.location.origin + '/callback',
{"}"});

// Start OAuth flow
const {"{"} url, pkce {"}"} = await client.oauth.getAuthorizationUrl({"{"}
  scopes: ['policy:social'],
{"}"});
sessionStorage.setItem('pkce_verifier', pkce.verifier);
window.location.href = url;</code
          ></pre>
      </div>

      <div class="code-example">
        <div class="code-header">
          <Code size={16} />
          <span>2. Exchange Code for Tokens</span>
        </div>
        <pre><code
            >// On callback page
const code = new URLSearchParams(location.search).get('code');
const verifier = sessionStorage.getItem('pkce_verifier');

const tokens = await client.oauth.exchangeCode(code, verifier);
// tokens.bunker_url  - NIP-46 bunker URL
// tokens.access_token - UCAN for REST RPC</code
          ></pre>
      </div>

      <div class="code-example">
        <div class="code-header">
          <Code size={16} />
          <span>3a. REST RPC (Low Latency)</span>
        </div>
        <pre><code
            >// Create RPC client from tokens
const rpc = client.createRpc(tokens);

// Or create directly
import {"{"} KeycastRpc {"}"} from 'keycast-login';
const rpc = new KeycastRpc({"{"}
  nostrApi: 'https://login.divine.video/api/nostr',
  accessToken: tokens.access_token,
{"}"});

const pubkey = await rpc.getPublicKey();
const signed = await rpc.signEvent(unsignedEvent);
const cipher = await rpc.nip44Encrypt(pubkey, 'secret');</code
          ></pre>
      </div>

      <div class="code-example">
        <div class="code-header">
          <Code size={16} />
          <span>3b. NIP-46 Bunker (via nostr-tools)</span>
        </div>
        <pre><code
            >// Use bunker URL with nostr-tools directly
import {"{"} BunkerSigner {"}"} from 'nostr-tools/nip46';

const bunkerUrl = tokens.bunker_url;
// bunker://&lt;pubkey&gt;?relay=...&amp;secret=...

const signer = new BunkerSigner(pool, bunkerUrl);
await signer.connect();

const pubkey = await signer.getPublicKey();
const signed = await signer.signEvent(unsignedEvent);</code
          ></pre>
      </div>
    </DemoSection>
  {/if}

  <!-- Library Info -->
  <aside class="library-info">
    <h3>Using keycast-login</h3>
    <p>Install the TypeScript client for easier integration:</p>
    <code class="install-command">npm install keycast-login</code>
    <a
      href="https://github.com/divinevideo/keycast/tree/main/keycast-login"
      class="text-link"
    >
      View documentation on GitHub →
    </a>
  </aside>
</div>

<style>
  /* Links */
  .text-link {
    color: var(--color-divine-green);
    text-decoration: none;
  }
  .text-link:hover {
    text-decoration: underline;
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.625rem 1.25rem;
    font-size: 0.875rem;
    font-weight: 500;
    border-radius: var(--radius-md);
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-primary {
    background: var(--color-divine-green) !important;
    color: var(--color-divine-bg) !important;
    border-color: var(--color-divine-green) !important;
  }

  .btn-primary:hover:not(:disabled) {
    background: #00a87a !important;
    box-shadow: 0 2px 8px rgba(0, 180, 136, 0.3);
  }

  .btn-secondary {
    background: var(--color-divine-muted);
    color: var(--color-divine-text);
    border-color: var(--color-divine-border);
  }

  .btn-secondary:hover:not(:disabled) {
    background: var(--color-divine-surface);
    border-color: var(--color-divine-text-tertiary);
  }

  .btn-outline {
    background: transparent;
    color: var(--color-divine-text);
    border-color: var(--color-divine-border);
  }

  .btn-outline:hover:not(:disabled) {
    background: var(--color-divine-muted);
    border-color: var(--color-divine-green);
  }

  .btn-ghost {
    background: transparent;
    color: var(--color-divine-text-secondary);
    border: none;
  }

  .btn-ghost:hover:not(:disabled) {
    background: var(--color-divine-muted);
    color: var(--color-divine-text);
  }

  .btn-sm {
    padding: 0.375rem 0.75rem;
    font-size: 0.8125rem;
  }

  /* Connected Banner */
  .connected-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem;
    background: rgba(0, 180, 136, 0.1);
    border: 1px solid var(--color-divine-green);
    border-radius: var(--radius-lg);
  }

  .connected-text {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 600;
    color: var(--color-divine-green);
  }

  .connected-text::before {
    content: "";
    width: 8px;
    height: 8px;
    background: var(--color-divine-green);
    border-radius: 50%;
  }

  /* Credentials */
  .credential-display {
    margin-top: 1rem;
  }

  .credential-display label {
    display: block;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-divine-text-secondary);
    margin-bottom: 0.25rem;
  }

  .credential-value {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    background: var(--color-divine-muted);
    border-radius: var(--radius-md);
    font-family: var(--font-mono);
    font-size: 0.875rem;
  }

  .credential-value code {
    flex: 1;
    word-break: break-all;
  }

  /* Connect Options */
  .connect-options {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .connect-option {
    padding: 1.25rem;
    background: var(--color-divine-muted);
    border-radius: var(--radius-lg);
  }

  .connect-option h3 {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0 0 0.5rem 0;
    font-size: 1rem;
    font-weight: 600;
  }

  .connect-option p {
    margin: 0 0 1rem 0;
    font-size: 0.875rem;
    color: var(--color-divine-text-secondary);
  }

  .divider {
    text-align: center;
    color: var(--color-divine-text-tertiary);
    font-size: 0.875rem;
  }

  /* Identity Display */
  .identity-display {
    margin-bottom: 1rem;
    padding: 0.75rem;
    background: var(--color-divine-surface);
    border: 1px solid var(--color-divine-border);
    border-radius: var(--radius-md);
  }

  .identity-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
  }

  .identity-label {
    font-family: var(--font-sans);
    font-weight: 500;
    color: var(--color-divine-text-secondary);
  }

  .button-group {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  /* Error Banner */
  .error-banner {
    margin-top: 1rem;
    padding: 0.75rem 1rem;
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-divine-error);
    border-radius: var(--radius-md);
    color: var(--color-divine-error);
    font-size: 0.875rem;
  }

  /* Form Elements */
  .action-group {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .form-group label,
  .form-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--color-divine-text-secondary);
  }

  input,
  textarea {
    background: var(--color-divine-muted);
    color: var(--color-divine-text);
    border: 1px solid var(--color-divine-border);
    border-radius: var(--radius-md);
    padding: 0.75rem;
    font-size: 0.875rem;
    font-family: var(--font-mono);
  }

  textarea {
    resize: vertical;
  }

  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--color-divine-green);
    box-shadow: 0 0 0 2px rgba(0, 180, 136, 0.2);
  }

  /* Method Selector */
  .method-selector {
    display: flex;
    gap: 0.5rem;
    padding: 0.25rem;
    background: var(--color-divine-muted);
    border-radius: var(--radius-md);
    width: fit-content;
  }

  .method-btn {
    padding: 0.5rem 1rem;
    font-size: 0.8125rem;
    font-weight: 500;
    background: transparent;
    color: var(--color-divine-text-secondary);
    border: none;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .method-btn:hover {
    background: var(--color-divine-surface);
    color: var(--color-divine-text);
  }

  .method-btn.active {
    background: var(--color-divine-green);
    color: var(--color-divine-bg);
  }

  /* Encrypt/Decrypt Row */
  .encrypt-decrypt-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
  }

  @media (max-width: 640px) {
    .encrypt-decrypt-row {
      grid-template-columns: 1fr;
    }
  }

  .flex-1 {
    flex: 1;
  }

  .mt-2 {
    margin-top: 0.5rem;
  }

  /* Code Examples */
  .code-example {
    background: var(--color-divine-muted);
    border: 1px solid var(--color-divine-border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .code-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 0.75rem;
    background: var(--color-divine-surface);
    border-bottom: 1px solid var(--color-divine-border);
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-divine-text-secondary);
  }

  .code-example pre {
    margin: 0;
    padding: 0.75rem;
    overflow-x: auto;
  }

  .code-example code {
    font-family: var(--font-mono);
    font-size: 0.8125rem;
    line-height: 1.5;
    color: var(--color-divine-text);
  }

  /* Library Info */
  .library-info {
    margin-top: 3rem;
    padding: 1.5rem;
    background: var(--color-divine-surface);
    border: 1px solid var(--color-divine-border);
    border-radius: var(--radius-xl);
  }

  .library-info h3 {
    margin: 0 0 0.5rem 0;
    font-size: 1rem;
    font-weight: 600;
  }

  .library-info p {
    margin: 0 0 1rem 0;
    font-size: 0.875rem;
    color: var(--color-divine-text-secondary);
  }

  .install-command {
    display: block;
    padding: 0.75rem 1rem;
    background: var(--color-divine-muted);
    border-radius: var(--radius-md);
    font-family: var(--font-mono);
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }

  :global(.text-divine-green) {
    color: var(--color-divine-green);
  }

  /* Hint text */
  .hint-text {
    margin-top: 0.75rem;
    font-size: 0.8125rem;
    color: var(--color-divine-text-tertiary);
    line-height: 1.5;
  }
</style>
