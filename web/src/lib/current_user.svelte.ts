import { nip19 } from "nostr-tools";

let currentUser: CurrentUser | null = $state(null);

class CurrentUser {
    pubkey: string;
    npub: string;
    authMethod: 'nip07' | 'cookie' | 'cloudflare' | null = $state(null);

    constructor(pubkey: string, authMethod: 'nip07' | 'cookie' | 'cloudflare' | null = null) {
        this.pubkey = pubkey;
        this.npub = nip19.npubEncode(pubkey);
        this.authMethod = authMethod;
    }
}

export function getCurrentUser(): CurrentUser | null {
    return currentUser;
}

export function setCurrentUser(
    pubkey: string | null,
    authMethod: 'nip07' | 'cookie' | 'cloudflare' | null = null
): CurrentUser | null {
    if (pubkey) {
        currentUser = new CurrentUser(pubkey, authMethod);
        if (typeof window !== 'undefined' && authMethod) {
            localStorage.setItem('keycast_auth_method', authMethod);
        }
    } else {
        currentUser = null;
        if (typeof window !== 'undefined') {
            localStorage.removeItem('keycast_auth_method');
        }
    }
    return currentUser;
}
