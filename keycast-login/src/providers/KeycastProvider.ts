// ABOUTME: Keycast provider - server-based authentication with KMS-backed NIP-46 signing
// ABOUTME: Handles registration, login, bunker URL retrieval, and remote signing

import type {
  Provider,
  NostrEvent,
  SignedNostrEvent,
  ConnectionState,
  KeycastProviderInfo,
} from '../types';
import { Nip46Client } from '../nip46/Nip46Client';

export interface KeycastProviderConfig {
  domain: string;       // 'login.divine.video'
  apiBase?: string;     // Custom API path (default: /api)
}

export class KeycastProvider implements Provider {
  name: string;
  type = 'keycast' as const;
  state: ConnectionState = 'disconnected';

  private domain: string;
  private apiBase: string;
  private token: string | null = null;
  private pubkey: string | null = null;
  private bunkerUrl: string | null = null;

  // NIP-46 connection
  private nip46Client: Nip46Client | null = null;

  constructor(config: KeycastProviderConfig) {
    this.domain = config.domain;
    this.apiBase = config.apiBase || '/api';
    this.name = `Keycast (${config.domain})`;
  }

  async connect(): Promise<void> {
    throw new Error('KeycastProvider.connect() requires authentication. Call authenticate() first.');
  }

  /**
   * Authenticate with email/password (register or login)
   * This is the golden path - try register, fallback to login
   */
  async authenticate(email: string, password: string): Promise<void> {
    this.state = 'connecting';

    try {
      // Try to register first
      const registerResponse = await fetch(`https://${this.domain}${this.apiBase}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const registerData = await registerResponse.json();

      if (registerResponse.ok) {
        // Registration succeeded
        this.token = registerData.token;
        this.pubkey = registerData.pubkey;
        await this.fetchBunkerUrl();
        await this.connectToSigner();
        this.state = 'connected';
        return;
      }

      // Registration failed - try login if account exists
      if (registerData.error?.includes('already registered')) {
        const loginResponse = await fetch(`https://${this.domain}${this.apiBase}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });

        const loginData = await loginResponse.json();

        if (loginResponse.ok) {
          this.token = loginData.token;
          this.pubkey = loginData.pubkey;
          await this.fetchBunkerUrl();
          await this.connectToSigner();
          this.state = 'connected';
          return;
        }

        throw new Error(loginData.error || 'Login failed');
      }

      throw new Error(registerData.error || 'Authentication failed');
    } catch (error) {
      this.state = 'error';
      throw error;
    }
  }

  private async fetchBunkerUrl(): Promise<void> {
    if (!this.token) {
      throw new Error('No auth token available');
    }

    const response = await fetch(`https://${this.domain}${this.apiBase}/user/bunker`, {
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to fetch bunker URL');
    }

    this.bunkerUrl = data.bunker_url;
  }

  private async connectToSigner(): Promise<void> {
    if (!this.bunkerUrl) {
      throw new Error('No bunker URL available');
    }

    // Parse bunker URL: bunker://PUBKEY?relay=RELAY&secret=SECRET
    const url = new URL(this.bunkerUrl);
    const bunkerPubkey = url.hostname;
    const relay = url.searchParams.get('relay');
    const secret = url.searchParams.get('secret');

    if (!relay || !secret) {
      throw new Error('Invalid bunker URL format');
    }

    // Create and connect NIP-46 client
    this.nip46Client = new Nip46Client({
      bunkerPubkey,
      relay,
      secret,
    });

    await this.nip46Client.connect();
  }

  async disconnect(): Promise<void> {
    // Clean up NIP-46 connection
    if (this.nip46Client) {
      await this.nip46Client.disconnect();
      this.nip46Client = null;
    }

    this.token = null;
    this.pubkey = null;
    this.bunkerUrl = null;
    this.state = 'disconnected';
  }

  async getPublicKey(): Promise<string> {
    if (!this.pubkey) {
      throw new Error('Not authenticated. Call authenticate() first.');
    }
    return this.pubkey;
  }

  async signEvent(event: NostrEvent): Promise<SignedNostrEvent> {
    if (!this.nip46Client) {
      throw new Error('Not connected to signer');
    }

    // Send sign request via NIP-46
    const signedEvent = await this.nip46Client.signEvent(event);
    return signedEvent as SignedNostrEvent;
  }

  // Optional encryption methods
  async nip04Encrypt(pubkey: string, plaintext: string): Promise<string> {
    if (!this.nip46Client) {
      throw new Error('Not connected to signer');
    }
    return await this.nip46Client.nip04Encrypt(pubkey, plaintext);
  }

  async nip04Decrypt(pubkey: string, ciphertext: string): Promise<string> {
    if (!this.nip46Client) {
      throw new Error('Not connected to signer');
    }
    return await this.nip46Client.nip04Decrypt(pubkey, ciphertext);
  }

  async nip44Encrypt(pubkey: string, plaintext: string): Promise<string> {
    if (!this.nip46Client) {
      throw new Error('Not connected to signer');
    }
    return await this.nip46Client.nip44Encrypt(pubkey, plaintext);
  }

  async nip44Decrypt(pubkey: string, ciphertext: string): Promise<string> {
    if (!this.nip46Client) {
      throw new Error('Not connected to signer');
    }
    return await this.nip46Client.nip44Decrypt(pubkey, ciphertext);
  }
}
