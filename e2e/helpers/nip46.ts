import WebSocket from "ws";

// Node.js doesn't have WebSocket global — nostr-tools needs it for relay connections
if (typeof globalThis.WebSocket === "undefined") {
  (globalThis as any).WebSocket = WebSocket;
}

import {
  BunkerSigner,
  parseBunkerInput,
} from "nostr-tools/nip46";
import { generateSecretKey } from "nostr-tools/pure";
import type { EventTemplate, VerifiedEvent } from "nostr-tools/pure";

export interface Nip46Client {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<VerifiedEvent>;
  nip44Encrypt(pubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(pubkey: string, ciphertext: string): Promise<string>;
  close(): Promise<void>;
}

export async function connectToBunker(
  bunkerUrl: string,
  timeoutMs = 30_000,
): Promise<Nip46Client> {
  const bp = await parseBunkerInput(bunkerUrl);
  if (!bp) {
    throw new Error(`Invalid bunker URL: ${bunkerUrl}`);
  }

  // Retry connection up to 3 times — the signer daemon's relay connection
  // may briefly drop and reconnect
  let lastError: Error | undefined;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const clientKey = generateSecretKey();
      const signer = BunkerSigner.fromBunker(clientKey, bp);

      await Promise.race([
        signer.connect(),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error("Bunker connection timed out")),
            timeoutMs,
          ),
        ),
      ]);

      return {
        getPublicKey: () => signer.getPublicKey(),
        signEvent: (event: EventTemplate) => signer.signEvent(event),
        nip44Encrypt: (pubkey: string, plaintext: string) =>
          signer.nip44Encrypt(pubkey, plaintext),
        nip44Decrypt: (pubkey: string, ciphertext: string) =>
          signer.nip44Decrypt(pubkey, ciphertext),
        close: () => signer.close(),
      };
    } catch (e) {
      lastError = e as Error;
      if (attempt < 2) {
        // Wait before retrying to let the signer daemon reconnect
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
  }

  throw lastError!;
}
