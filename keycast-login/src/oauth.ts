// ABOUTME: OAuth client for Keycast authorization
// ABOUTME: Handles authorization URL generation, token exchange, and PKCE

import { generatePkce } from './pkce';
import type {
  KeycastClientConfig,
  OAuthError,
  PkceChallenge,
  StoredCredentials,
  TokenResponse,
} from './types';

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
  private pendingPkce: PkceChallenge | null = null;

  constructor(config: KeycastClientConfig) {
    this.config = config;
    this.fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Generate authorization URL for OAuth flow
   *
   * @param options - Authorization options
   * @returns Authorization URL and PKCE verifier
   */
  async getAuthorizationUrl(options: {
    scopes?: string[];
    nsec?: string; // For BYOK flow - pubkey is derived automatically
    defaultRegister?: boolean;
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

    // Derive pubkey from nsec if provided (BYOK flow)
    if (options.nsec) {
      const pubkey = await derivePublicKeyFromNsec(options.nsec);
      url.searchParams.set('byok_pubkey', pubkey);
    }

    return { url: url.toString(), pkce };
  }

  /**
   * Exchange authorization code for tokens
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

    return data as TokenResponse;
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
