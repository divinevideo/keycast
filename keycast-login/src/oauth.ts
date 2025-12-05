// ABOUTME: OAuth client for Keycast authorization
// ABOUTME: Handles authorization URL generation, token exchange, and PKCE

import { generatePkce } from './pkce';
import type {
  KeycastClientConfig,
  KeycastStorage,
  OAuthError,
  PkceChallenge,
  StoredCredentials,
  TokenResponse,
} from './types';

/** Storage key for session credentials */
const STORAGE_KEY_SESSION = 'keycast_session';
/** Storage key for authorization handle (for silent re-auth when session expires) */
const STORAGE_KEY_HANDLE = 'keycast_auth_handle';

/**
 * In-memory storage fallback when no storage is provided
 */
class MemoryStorage implements KeycastStorage {
  private data = new Map<string, string>();

  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }
}

/**
 * Derive public key from nsec using nostr-tools (optional peer dependency)
 * Uses dynamic import to avoid hard dependency on nostr-tools
 */
async function derivePublicKeyFromNsec(nsec: string): Promise<string> {
  try {
    // Use Function constructor to avoid TypeScript module resolution
    const importModule = new Function('specifier', 'return import(specifier)');
    const nip19 = await importModule('nostr-tools/nip19');
    const pure = await importModule('nostr-tools/pure');
    const decoded = nip19.decode(nsec);
    if (decoded.type !== 'nsec') {
      throw new Error('Not a valid nsec');
    }
    return pure.getPublicKey(decoded.data);
  } catch (e) {
    throw new Error(`Invalid nsec or nostr-tools not installed: ${e instanceof Error ? e.message : 'unknown error'}`);
  }
}

/**
 * OAuth client for Keycast authorization
 */
export class KeycastOAuth {
  private config: KeycastClientConfig;
  private fetch: typeof globalThis.fetch;
  private storage: KeycastStorage;
  private pendingPkce: PkceChallenge | null = null;

  constructor(config: KeycastClientConfig) {
    this.config = config;
    this.fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
    this.storage = config.storage ?? new MemoryStorage();
  }

  /**
   * Get stored session from storage
   * Returns null if no session or session is expired
   */
  getSession(): StoredCredentials | null {
    const json = this.storage.getItem(STORAGE_KEY_SESSION);
    if (!json) return null;

    try {
      const credentials = JSON.parse(json) as StoredCredentials;
      if (this.isExpired(credentials)) {
        return null;
      }
      return credentials;
    } catch {
      return null;
    }
  }

  /**
   * Get stored authorization handle (survives logout)
   */
  getAuthorizationHandle(): string | null {
    return this.storage.getItem(STORAGE_KEY_HANDLE);
  }

  /**
   * Clear all session data including authorization handle
   * Use this when user explicitly logs out - clears everything for security
   */
  logout(): void {
    this.storage.removeItem(STORAGE_KEY_SESSION);
    this.storage.removeItem(STORAGE_KEY_HANDLE);
  }

  private saveSession(credentials: StoredCredentials): void {
    this.storage.setItem(STORAGE_KEY_SESSION, JSON.stringify(credentials));
    if (credentials.authorizationHandle) {
      this.storage.setItem(STORAGE_KEY_HANDLE, credentials.authorizationHandle);
    }
  }

  /**
   * Generate authorization URL for OAuth flow
   * Automatically uses stored authorization handle for silent re-auth if available
   *
   * @param options - Authorization options
   * @returns Authorization URL and PKCE verifier
   */
  async getAuthorizationUrl(options: {
    scopes?: string[];
    nsec?: string; // For BYOK flow - pubkey is derived automatically
    defaultRegister?: boolean;
    authorizationHandle?: string; // Override stored handle for silent re-authentication
  } = {}): Promise<{ url: string; pkce: PkceChallenge }> {
    const pkce = await generatePkce(options.nsec);
    this.pendingPkce = pkce;

    const url = new URL(`${this.config.serverUrl}/api/oauth/authorize`);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', options.scopes?.join(' ') ?? 'policy:social');
    url.searchParams.set('code_challenge', pkce.challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    if (options.defaultRegister) {
      url.searchParams.set('default_register', 'true');
    }

    // Use provided handle, or auto-load from storage for silent re-authentication
    const handle = options.authorizationHandle ?? this.getAuthorizationHandle();
    if (handle) {
      url.searchParams.set('authorization_handle', handle);
    }

    // Derive pubkey from nsec if provided (BYOK flow)
    if (options.nsec) {
      const pubkey = await derivePublicKeyFromNsec(options.nsec);
      url.searchParams.set('byok_pubkey', pubkey);
    }

    return { url: url.toString(), pkce };
  }

  /**
   * Exchange authorization code for tokens
   * Automatically saves session to storage after successful exchange
   *
   * @param code - Authorization code from callback
   * @param verifier - PKCE verifier (optional if stored from getAuthorizationUrl)
   * @returns Token response with bunker_url and optional access_token
   */
  async exchangeCode(code: string, verifier?: string): Promise<TokenResponse> {
    const codeVerifier = verifier ?? this.pendingPkce?.verifier;

    if (!codeVerifier) {
      throw new Error('No PKCE verifier available. Call getAuthorizationUrl first or provide verifier.');
    }

    const response = await this.fetch(`${this.config.serverUrl}/api/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: this.config.clientId,
        redirect_uri: this.config.redirectUri,
        code_verifier: codeVerifier,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      const error = data as OAuthError;
      throw new Error(error.error_description ?? error.error ?? 'Token exchange failed');
    }

    // Clear pending PKCE after successful exchange
    this.pendingPkce = null;

    const tokenResponse = data as TokenResponse;

    // Auto-save session and authorization handle to storage
    const credentials = this.toStoredCredentials(tokenResponse);
    this.saveSession(credentials);

    return tokenResponse;
  }

  /**
   * Parse callback URL and extract authorization code
   *
   * @param url - Callback URL (window.location.href)
   * @returns Authorization code or error
   */
  parseCallback(url: string): { code: string } | { error: string; description?: string } {
    const parsed = new URL(url);
    const code = parsed.searchParams.get('code');
    const error = parsed.searchParams.get('error');

    if (error) {
      return {
        error,
        description: parsed.searchParams.get('error_description') ?? undefined,
      };
    }

    if (code) {
      return { code };
    }

    return { error: 'missing_code', description: 'No authorization code in callback URL' };
  }

  /**
   * Convert TokenResponse to StoredCredentials
   */
  toStoredCredentials(response: TokenResponse): StoredCredentials {
    const expiresAt = response.expires_in > 0
      ? Date.now() + response.expires_in * 1000
      : undefined;

    return {
      bunkerUrl: response.bunker_url,
      accessToken: response.access_token,
      expiresAt,
      authorizationHandle: response.authorization_handle,
    };
  }

  /**
   * Check if stored credentials are expired
   */
  isExpired(credentials: StoredCredentials): boolean {
    if (!credentials.expiresAt) return false;
    return Date.now() >= credentials.expiresAt;
  }
}
