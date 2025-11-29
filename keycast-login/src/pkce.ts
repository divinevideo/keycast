// ABOUTME: PKCE (Proof Key for Code Exchange) utilities
// ABOUTME: Generates code verifier and challenge for secure OAuth flow

import type { PkceChallenge } from './types';

/**
 * Base64 URL encode a buffer
 */
function base64URLEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a random code verifier
 */
function generateVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64URLEncode(bytes.buffer);
}

/**
 * Generate SHA-256 hash of a string
 */
async function sha256(str: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  return crypto.subtle.digest('SHA-256', encoder.encode(str));
}

/**
 * Generate PKCE challenge from verifier
 *
 * @param nsec - Optional nsec to embed in verifier for BYOK flow
 * @returns PKCE challenge with verifier and code_challenge
 */
export async function generatePkce(nsec?: string): Promise<PkceChallenge> {
  const randomPart = generateVerifier();

  // Embed nsec in verifier if provided (BYOK flow)
  // Format: {random}.{nsec}
  const verifier = nsec ? `${randomPart}.${nsec}` : randomPart;

  const hashBuffer = await sha256(verifier);
  const challenge = base64URLEncode(hashBuffer);

  return { verifier, challenge };
}

/**
 * Validate a PKCE challenge
 *
 * @param verifier - The code verifier
 * @param challenge - The expected code challenge
 * @param method - The challenge method (plain or S256)
 * @returns true if valid
 */
export async function validatePkce(
  verifier: string,
  challenge: string,
  method: 'plain' | 'S256' = 'S256'
): Promise<boolean> {
  if (method === 'plain') {
    return verifier === challenge;
  }

  const hashBuffer = await sha256(verifier);
  const computed = base64URLEncode(hashBuffer);
  return computed === challenge;
}
