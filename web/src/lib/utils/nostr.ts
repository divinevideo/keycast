import { nip19 } from "nostr-tools";

export function truncatedNpubForPubkey(pubkey?: string, maxLength = 9) {
    if (!pubkey) return undefined;
    return nip19.npubEncode(pubkey).slice(0, maxLength);
}

export function pubkeyFromNpubOrHex(input: string): string {
    if (input.startsWith("npub1")) {
        const { data } = nip19.decode(input);
        return data as string;
    }
    return input;
}

export function npubFromPubkey(pubkey: string): string {
    return nip19.npubEncode(pubkey);
}
