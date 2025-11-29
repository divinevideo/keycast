import { describe, expect, it, vi } from 'vitest';
import { KeycastRpc } from '../src/rpc';

describe('KeycastRpc', () => {
  const config = {
    nostrApi: 'https://login.divine.video/api/nostr',
    accessToken: 'test_token',
  };

  describe('getPublicKey', () => {
    it('should return public key', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            result: 'abc123def456',
          }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });
      const pubkey = await rpc.getPublicKey();

      expect(pubkey).toBe('abc123def456');
      expect(mockFetch).toHaveBeenCalledWith(
        config.nostrApi,
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: 'Bearer test_token',
          }),
          body: JSON.stringify({ method: 'get_public_key', params: [] }),
        })
      );
    });

    it('should throw on error', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        json: () =>
          Promise.resolve({
            error: 'Unauthorized',
          }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });

      await expect(rpc.getPublicKey()).rejects.toThrow('Unauthorized');
    });
  });

  describe('signEvent', () => {
    it('should sign event', async () => {
      const signedEvent = {
        id: 'event123',
        pubkey: 'abc123',
        kind: 1,
        content: 'Hello!',
        tags: [],
        created_at: 1234567890,
        sig: 'sig123',
      };

      const mockFetch = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({ result: signedEvent }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });
      const result = await rpc.signEvent({
        kind: 1,
        content: 'Hello!',
        tags: [],
        created_at: 1234567890,
        pubkey: 'abc123',
      });

      expect(result).toEqual(signedEvent);
      expect(result.id).toBe('event123');
      expect(result.sig).toBe('sig123');
    });
  });

  describe('nip44Encrypt', () => {
    it('should encrypt plaintext', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({ result: 'encrypted_data' }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });
      const ciphertext = await rpc.nip44Encrypt('recipient_pubkey', 'secret message');

      expect(ciphertext).toBe('encrypted_data');
      expect(mockFetch).toHaveBeenCalledWith(
        config.nostrApi,
        expect.objectContaining({
          body: JSON.stringify({
            method: 'nip44_encrypt',
            params: ['recipient_pubkey', 'secret message'],
          }),
        })
      );
    });
  });

  describe('nip44Decrypt', () => {
    it('should decrypt ciphertext', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({ result: 'decrypted message' }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });
      const plaintext = await rpc.nip44Decrypt('sender_pubkey', 'encrypted_data');

      expect(plaintext).toBe('decrypted message');
    });
  });

  describe('nip04Encrypt', () => {
    it('should encrypt plaintext with NIP-04', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({ result: 'nip04_encrypted' }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });
      const ciphertext = await rpc.nip04Encrypt('recipient_pubkey', 'secret');

      expect(ciphertext).toBe('nip04_encrypted');
    });
  });

  describe('nip04Decrypt', () => {
    it('should decrypt ciphertext with NIP-04', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({ result: 'nip04_decrypted' }),
      });

      const rpc = new KeycastRpc({ ...config, fetch: mockFetch as any });
      const plaintext = await rpc.nip04Decrypt('sender_pubkey', 'encrypted');

      expect(plaintext).toBe('nip04_decrypted');
    });
  });

  describe('fromCredentials', () => {
    it('should create client from valid credentials', () => {
      const rpc = KeycastRpc.fromCredentials({
        nostrApi: 'https://api.test',
        accessToken: 'token',
      });

      expect(rpc).toBeInstanceOf(KeycastRpc);
    });

    it('should return null for missing nostrApi', () => {
      const rpc = KeycastRpc.fromCredentials({
        accessToken: 'token',
      });

      expect(rpc).toBeNull();
    });

    it('should return null for missing accessToken', () => {
      const rpc = KeycastRpc.fromCredentials({
        nostrApi: 'https://api.test',
      });

      expect(rpc).toBeNull();
    });
  });
});
