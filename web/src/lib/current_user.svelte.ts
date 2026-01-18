import ndk from "$lib/ndk.svelte";
import type { NDKUser } from "@nostr-dev-kit/ndk";

let currentUser: CurrentUser | null = $state(null);

class CurrentUser {
    /** The NDKUser instance representing the current logged in user */
    user: NDKUser | null = $state(null);

    /** Array of pubkeys that the current user follows */
    follows: string[] = $state([]);

    /** Authentication method used by this user */
    authMethod: 'nip07' | 'cookie' | null = $state(null);

    constructor(pubkey: string, authMethod: 'nip07' | 'cookie' | null = null) {
        this.user = ndk.getUser({ pubkey });
        this.authMethod = authMethod;
        if (this.user) {
            this.fetchUserFollows();
        }
    }

    async fetchUserFollows(): Promise<string[]> {
        if (this.user) {
            const followsSet = await this.user.follows();
            const follows = Array.from(followsSet).map((user) => user.pubkey);
            this.follows = follows;
            return follows;
        }
        return Promise.resolve([]);
    }
}

export function getCurrentUser(): CurrentUser | null {
    return currentUser;
}

export function setCurrentUser(
    npub: string | null,
    authMethod: 'nip07' | 'cookie' | null = null
): CurrentUser | null {
    if (npub) {
        currentUser = new CurrentUser(npub, authMethod);
        // Persist auth method to localStorage
        if (typeof window !== 'undefined' && authMethod) {
            localStorage.setItem('keycast_auth_method', authMethod);
        }
    } else {
        currentUser = null;
        // Clear auth method on logout
        if (typeof window !== 'undefined') {
            localStorage.removeItem('keycast_auth_method');
        }
    }
    return currentUser;
}
