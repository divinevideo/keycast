// ABOUTME: RPC client for Keycast Nostr API
// ABOUTME: Low-latency alternative to NIP-46 relay-based signing

import type { RpcResponse, SignedEvent, UnsignedEvent } from './types';

/**
 * RPC client for Keycast Nostr API
 *
 * Provides a low-latency REST alternative to NIP-46 relay-based signing.
 * Mirrors the NIP-46 method signatures for easy migration.
 */
export class KeycastRpc {
  private nostrApi: string;
  private accessToken: string;
  private fetch: typeof globalThis.fetch;

  constructor(options: {
    nostrApi: string;
    accessToken: string;
    fetch?: typeof fetch;
  }) {
    this.nostrApi = options.nostrApi;
    this.accessToken = options.accessToken;
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Make an RPC call to the Keycast API
   */
  private async call<T>(method: string, params: unknown[] = []): Promise<T> {
    const response = await this.fetch(this.nostrApi, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.accessToken}`,
      },
      body: JSON.stringify({ method, params }),
    });

    const data: RpcResponse<T> = await response.json();

    if (data.error) {
      throw new Error(data.error);
    }

    if (data.result === undefined) {
      throw new Error('No result in RPC response');
    }

    return data.result;
  }

  /**
   * Get the user's public key (hex format)
   *
   * Mirrors NIP-46 get_public_key method
   */
  async getPublicKey(): Promise<string> {
    return this.call<string>('get_public_key', []);
  }

  /**
   * Sign an unsigned Nostr event
   *
   * Mirrors NIP-46 sign_event method
   *
   * @param event - Unsigned event to sign
   * @returns Signed event with id and sig
   */
  async signEvent(event: UnsignedEvent): Promise<SignedEvent> {
    return this.call<SignedEvent>('sign_event', [event]);
  }

  /**
   * Encrypt plaintext using NIP-44
   *
   * Mirrors NIP-46 nip44_encrypt method
   *
   * @param recipientPubkey - Recipient's public key (hex)
   * @param plaintext - Text to encrypt
   * @returns Encrypted ciphertext
   */
  async nip44Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.call<string>('nip44_encrypt', [recipientPubkey, plaintext]);
  }

  /**
   * Decrypt ciphertext using NIP-44
   *
   * Mirrors NIP-46 nip44_decrypt method
   *
   * @param senderPubkey - Sender's public key (hex)
   * @param ciphertext - Text to decrypt
   * @returns Decrypted plaintext
   */
  async nip44Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.call<string>('nip44_decrypt', [senderPubkey, ciphertext]);
  }

  /**
   * Encrypt plaintext using NIP-04 (legacy)
   *
   * Mirrors NIP-46 nip04_encrypt method
   *
   * @param recipientPubkey - Recipient's public key (hex)
   * @param plaintext - Text to encrypt
   * @returns Encrypted ciphertext
   */
  async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.call<string>('nip04_encrypt', [recipientPubkey, plaintext]);
  }

  /**
   * Decrypt ciphertext using NIP-04 (legacy)
   *
   * Mirrors NIP-46 nip04_decrypt method
   *
   * @param senderPubkey - Sender's public key (hex)
   * @param ciphertext - Text to decrypt
   * @returns Decrypted plaintext
   */
  async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.call<string>('nip04_decrypt', [senderPubkey, ciphertext]);
  }

  /**
   * Create a new RPC client from stored credentials and server URL
   *
   * @param serverUrl - The Keycast server URL (e.g., "https://login.divine.video")
   * @param accessToken - The UCAN access token from OAuth flow
   */
  static fromServerUrl(serverUrl: string, accessToken: string): KeycastRpc {
    return new KeycastRpc({
      nostrApi: `${serverUrl}/api/nostr`,
      accessToken,
    });
  }
}
