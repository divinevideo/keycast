import { describe, expect, it } from 'vitest';
import { generatePkce, validatePkce } from '../src/pkce';

describe('PKCE', () => {
  describe('generatePkce', () => {
    it('should generate verifier and challenge', async () => {
      const pkce = await generatePkce();

      expect(pkce.verifier).toBeDefined();
      expect(pkce.challenge).toBeDefined();
      expect(pkce.verifier.length).toBeGreaterThan(20);
      expect(pkce.challenge.length).toBeGreaterThan(20);
    });

    it('should generate unique verifiers', async () => {
      const pkce1 = await generatePkce();
      const pkce2 = await generatePkce();

      expect(pkce1.verifier).not.toBe(pkce2.verifier);
      expect(pkce1.challenge).not.toBe(pkce2.challenge);
    });

    it('should embed nsec in verifier for BYOK', async () => {
      const nsec = 'nsec1test123';
      const pkce = await generatePkce(nsec);

      expect(pkce.verifier).toContain(nsec);
      expect(pkce.verifier).toContain('.');
    });
  });

  describe('validatePkce', () => {
    it('should validate S256 challenge', async () => {
      const pkce = await generatePkce();
      const isValid = await validatePkce(pkce.verifier, pkce.challenge, 'S256');

      expect(isValid).toBe(true);
    });

    it('should reject invalid challenge', async () => {
      const pkce = await generatePkce();
      const isValid = await validatePkce(pkce.verifier, 'invalid-challenge', 'S256');

      expect(isValid).toBe(false);
    });

    it('should validate plain challenge', async () => {
      const verifier = 'test-verifier';
      const isValid = await validatePkce(verifier, verifier, 'plain');

      expect(isValid).toBe(true);
    });

    it('should reject mismatched plain challenge', async () => {
      const isValid = await validatePkce('verifier1', 'verifier2', 'plain');

      expect(isValid).toBe(false);
    });
  });
});
