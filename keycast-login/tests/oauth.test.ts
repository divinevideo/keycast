import { describe, expect, it, vi } from 'vitest';
import { KeycastOAuth } from '../src/oauth';

describe('KeycastOAuth', () => {
  const config = {
    serverUrl: 'https://login.divine.video',
    clientId: 'test-app',
    redirectUri: 'http://localhost:3000/callback',
  };

  describe('getAuthorizationUrl', () => {
    it('should generate valid authorization URL', async () => {
      const oauth = new KeycastOAuth(config);
      const { url, pkce } = await oauth.getAuthorizationUrl();

      expect(url).toContain(config.serverUrl);
      expect(url).toContain('client_id=test-app');
      expect(url).toContain('redirect_uri=');
      expect(url).toContain('code_challenge=');
      expect(url).toContain('code_challenge_method=S256');
      expect(pkce.verifier).toBeDefined();
      expect(pkce.challenge).toBeDefined();
    });

    it('should include custom scopes', async () => {
      const oauth = new KeycastOAuth(config);
      const { url } = await oauth.getAuthorizationUrl({
        scopes: ['sign_event', 'encrypt'],
      });

      expect(url).toContain('scope=sign_event+encrypt');
    });

    it('should include BYOK parameters when nsec provided', async () => {
      // Note: This test requires nostr-tools to be installed
      // The nsec below is a test vector, not a real key
      const testNsec = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';
      const expectedPubkey = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';

      const oauth = new KeycastOAuth(config);
      const { url, pkce } = await oauth.getAuthorizationUrl({
        nsec: testNsec,
        defaultRegister: true,
      });

      expect(url).toContain(`byok_pubkey=${expectedPubkey}`);
      expect(url).toContain('default_register=true');
      expect(pkce.verifier).toContain(testNsec);
    });
  });

  describe('parseCallback', () => {
    it('should parse authorization code', () => {
      const oauth = new KeycastOAuth(config);
      const result = oauth.parseCallback(
        'http://localhost:3000/callback?code=abc123'
      );

      expect(result).toEqual({ code: 'abc123' });
    });

    it('should parse error', () => {
      const oauth = new KeycastOAuth(config);
      const result = oauth.parseCallback(
        'http://localhost:3000/callback?error=access_denied&error_description=User%20denied'
      );

      expect(result).toEqual({
        error: 'access_denied',
        description: 'User denied',
      });
    });

    it('should return error for missing code', () => {
      const oauth = new KeycastOAuth(config);
      const result = oauth.parseCallback('http://localhost:3000/callback');

      expect('error' in result).toBe(true);
    });
  });

  describe('exchangeCode', () => {
    it('should exchange code for tokens', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            bunker_url: 'bunker://abc?relay=wss://relay.test&secret=xyz',
            access_token: 'ucan_token',
            token_type: 'Bearer',
            expires_in: 86400,
            scope: 'sign_event',
          }),
      });

      const oauth = new KeycastOAuth({ ...config, fetch: mockFetch as any });

      // Generate URL first to store PKCE
      await oauth.getAuthorizationUrl();

      const tokens = await oauth.exchangeCode('test_code');

      expect(tokens.bunker_url).toBeDefined();
      expect(tokens.access_token).toBe('ucan_token');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://login.divine.video/api/oauth/token',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );
    });

    it('should throw on error response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        json: () =>
          Promise.resolve({
            error: 'invalid_grant',
            error_description: 'Code expired',
          }),
      });

      const oauth = new KeycastOAuth({ ...config, fetch: mockFetch as any });
      await oauth.getAuthorizationUrl();

      await expect(oauth.exchangeCode('expired_code')).rejects.toThrow(
        'Code expired'
      );
    });

    it('should throw if no PKCE verifier', async () => {
      const oauth = new KeycastOAuth(config);

      await expect(oauth.exchangeCode('code')).rejects.toThrow(
        'No PKCE verifier'
      );
    });
  });

  describe('toStoredCredentials', () => {
    it('should convert token response', () => {
      const oauth = new KeycastOAuth(config);
      const response = {
        bunker_url: 'bunker://abc',
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'sign_event',
      };

      const credentials = oauth.toStoredCredentials(response);

      expect(credentials.bunkerUrl).toBe('bunker://abc');
      expect(credentials.accessToken).toBe('token');
      expect(credentials.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should handle zero expiry', () => {
      const oauth = new KeycastOAuth(config);
      const response = {
        bunker_url: 'bunker://abc',
        token_type: 'Bearer',
        expires_in: 0,
      };

      const credentials = oauth.toStoredCredentials(response);

      expect(credentials.expiresAt).toBeUndefined();
    });
  });

  describe('isExpired', () => {
    it('should return false for non-expired credentials', () => {
      const oauth = new KeycastOAuth(config);
      const credentials = {
        bunkerUrl: 'bunker://abc',
        expiresAt: Date.now() + 3600000,
      };

      expect(oauth.isExpired(credentials)).toBe(false);
    });

    it('should return true for expired credentials', () => {
      const oauth = new KeycastOAuth(config);
      const credentials = {
        bunkerUrl: 'bunker://abc',
        expiresAt: Date.now() - 1000,
      };

      expect(oauth.isExpired(credentials)).toBe(true);
    });

    it('should return false for credentials without expiry', () => {
      const oauth = new KeycastOAuth(config);
      const credentials = {
        bunkerUrl: 'bunker://abc',
      };

      expect(oauth.isExpired(credentials)).toBe(false);
    });
  });
});
