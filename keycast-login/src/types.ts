// ABOUTME: Type definitions for Keycast client library
// ABOUTME: Includes OAuth response types and RPC request/response formats

/**
 * OAuth token response from Keycast server
 */
export interface TokenResponse {
  /** NIP-46 bunker URL for remote signing */
  bunker_url: string;
  /** UCAN access token for REST RPC API */
  access_token?: string;
  /** Token type, always "Bearer" */
  token_type: string;
  /** Token expiry in seconds */
  expires_in: number;
  /** Granted OAuth scopes */
  scope?: string;
}

/**
 * OAuth error response
 */
export interface OAuthError {
  error: string;
  error_description?: string;
}

/**
 * RPC request format (mirrors NIP-46)
 */
export interface RpcRequest {
  method: string;
  params: unknown[];
}

/**
 * RPC response format
 */
export interface RpcResponse<T = unknown> {
  result?: T;
  error?: string;
}

/**
 * Unsigned Nostr event for signing
 */
export interface UnsignedEvent {
  kind: number;
  content: string;
  tags: string[][];
  created_at: number;
  pubkey: string;
}

/**
 * Signed Nostr event
 */
export interface SignedEvent extends UnsignedEvent {
  id: string;
  sig: string;
}

/**
 * PKCE challenge and verifier pair
 */
export interface PkceChallenge {
  verifier: string;
  challenge: string;
}

/**
 * Keycast client configuration
 */
export interface KeycastClientConfig {
  /** Keycast server URL (e.g., "https://login.divine.video") */
  serverUrl: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth redirect URI */
  redirectUri: string;
  /** Optional custom fetch implementation */
  fetch?: typeof fetch;
}

/**
 * Stored OAuth credentials
 */
export interface StoredCredentials {
  bunkerUrl: string;
  accessToken?: string;
  expiresAt?: number;
}
