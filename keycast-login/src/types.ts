// ABOUTME: TypeScript type definitions for keycast-login
// ABOUTME: Defines interfaces for configuration, events, and providers

export interface KeycastProviderInfo {
  domain: string;          // 'login.divine.video'
  name: string;            // 'Divine'
  description?: string;    // Optional description
  apiBase?: string;        // Custom API path (default: /api)
  logo?: string;           // Optional logo URL
}

export interface KeycastLoginConfig {
  // Keycast provider settings
  keycast?: {
    mode?: 'auto' | 'select' | 'custom';  // How to handle provider selection
    defaultDomain?: string;                // Override auto-detection
    knownProviders?: KeycastProviderInfo[]; // List of Keycast servers
    allowCustom?: boolean;                 // Allow users to enter any URL
  };

  // Alternative authentication methods
  enableNip07?: boolean;        // Browser extensions (Alby, nos2x, etc.)
  enableCustomBunker?: boolean; // Allow users to paste bunker:// URLs

  // UI settings
  headless?: boolean;           // Disable built-in modal
  theme?: 'dark' | 'light';     // Modal theme
  brandColor?: string;          // Primary color override

  // Behavior
  autoConnect?: boolean;        // Try to connect on initialization
  rememberChoice?: boolean;     // Remember user's provider choice
  cacheTimeout?: number;        // Session cache duration (ms)
}

export interface NostrEvent {
  kind: number;
  created_at: number;
  tags: string[][];
  content: string;
  pubkey?: string;
}

export interface SignedNostrEvent extends NostrEvent {
  id: string;
  pubkey: string;
  sig: string;
}

export interface AuthCredentials {
  email: string;
  password: string;
}

export type ProviderType = 'keycast' | 'nip07' | 'bunker';

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface Provider {
  name: string;
  type: ProviderType;
  state: ConnectionState;

  connect(): Promise<void>;
  disconnect(): Promise<void>;  // Changed to async for cleanup
  getPublicKey(): Promise<string>;
  signEvent(event: NostrEvent): Promise<SignedNostrEvent>;

  // Optional NIP-04/44 encryption (not all providers support)
  nip04Encrypt?(pubkey: string, plaintext: string): Promise<string>;
  nip04Decrypt?(pubkey: string, ciphertext: string): Promise<string>;
  nip44Encrypt?(pubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt?(pubkey: string, ciphertext: string): Promise<string>;
}

// Event types with proper typing
export type KeycastEvent =
  | { type: 'connected'; pubkey: string }
  | { type: 'disconnected' }
  | { type: 'error'; error: Error }
  | { type: 'provider-changed'; provider: ProviderType; name: string }
  | { type: 'state-changed'; state: ConnectionState };

export type EventHandler<T extends KeycastEvent = KeycastEvent> = (event: T) => void;

export interface EventEmitter {
  on<T extends KeycastEvent['type']>(
    event: T,
    handler: EventHandler<Extract<KeycastEvent, { type: T }>>
  ): void;
  off<T extends KeycastEvent['type']>(
    event: T,
    handler: EventHandler<Extract<KeycastEvent, { type: T }>>
  ): void;
  emit(event: KeycastEvent): void;
}
