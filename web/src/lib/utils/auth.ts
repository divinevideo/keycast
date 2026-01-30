import { browser } from "$app/environment";
import { goto } from "$app/navigation";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import type NDK from "@nostr-dev-kit/ndk";
import {
    NDKEvent,
    NDKKind,
    NDKNip07Signer,
    type NDKUser,
} from "@nostr-dev-kit/ndk";
import toast from "svelte-hot-french-toast";
import { getViteDomain, getAllowedPubkeys } from "$lib/utils/env";

export enum SigninMethod {
    Nip07 = "nip07",
    NostrLogin = "nostr-login",
    // Nip46 = "nip46",
    // PK = "pk",
}

function isAllowedPubkey(pubkey: string) {
    const allowedPubkeys = getAllowedPubkeys();
    return allowedPubkeys && allowedPubkeys.includes(pubkey);
}

/**
 * Attempt to signin with the same method that was previously used, or default to NIP-07 extension
 * For NIP-07, performs NIP-98 authentication against /api/auth/login to get session cookie
 */
export async function signin(
    ndk: NDK,
    bunkerNDK?: NDK,
    method?: SigninMethod,
    token?: string,
    user?: NDKUser,
): Promise<NDKUser | null> {
    // We only handle NIP-07 or nostr login for now
    let signedInUser: NDKUser | null = user || null;
    if (method === SigninMethod.Nip07) {
        signedInUser = await nip07Login(ndk);
    }
    if (signedInUser) {
        signedInUser.ndk = ndk;
        ndk.activeUser = signedInUser;
        const alreadySignedIn = !!getCurrentUser();
        if (!alreadySignedIn) {
            toast.success("Signed in successfully");
        }
        // NIP-07 admins go to dashboard, regular users go to teams
        goto(method === SigninMethod.Nip07 ? "/" : "/teams");
    }
    return signedInUser;
}

/**
 * Authenticate admin user via NIP-07 extension using NIP-98 HTTP Auth
 * Signs a kind 27235 event and sends it to /api/auth/login
 */
async function nip07Login(ndk: NDK): Promise<NDKUser | null> {
    if (!browser || !window.nostr) {
        toast.error("NIP-07 extension not found");
        return null;
    }

    try {
        // Get user from NIP-07 extension
        const signer = new NDKNip07Signer();
        ndk.signer = signer;
        const user = await signer.user();

        // Client-side check for allowed pubkeys (server also validates)
        if (!isAllowedPubkey(user.pubkey)) {
            toast.error("Your pubkey is not authorized for admin access");
            return null;
        }

        // Build NIP-98 auth event for login endpoint
        const apiBase = getViteDomain();
        const url = `${apiBase}/api/auth/login`;

        const authEvent = new NDKEvent(ndk, {
            kind: NDKKind.HttpAuth,
            content: "",
            pubkey: user.pubkey,
            created_at: Math.floor(Date.now() / 1000),
            tags: [
                ["u", url],
                ["method", "POST"],
            ],
        });

        // Sign the event with NIP-07 extension
        await authEvent.sign();

        // Send NIP-98 auth to login endpoint
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Nostr ${btoa(JSON.stringify(authEvent.rawEvent()))}`,
                'Origin': window.location.origin,
            },
            credentials: 'include',
        });

        if (response.ok) {
            const data = await response.json();
            setCurrentUser(data.pubkey, 'nip07');
            document.cookie = `keycastUserPubkey=${data.pubkey}; max-age=1209600; SameSite=Lax; Secure; path=/`;
            return user;
        } else if (response.status === 403) {
            toast.error("Your pubkey is not authorized for admin access");
            return null;
        } else {
            const error = await response.json().catch(() => ({ error: response.statusText }));
            toast.error(error.error || "Login failed");
            return null;
        }
    } catch (error) {
        console.error("NIP-07 login error:", error);
        toast.error(error instanceof Error ? error.message : "Login failed");
        return null;
    }
}

/**
 * Signs the user out.
 */
export async function signout(ndk: NDK) {
    // Call API logout endpoint to clear server-side session cookie
    try {
        const response = await fetch(`${getViteDomain()}/api/auth/logout`, {
            method: 'POST',
            credentials: 'include',
        });
        if (!response.ok) {
            console.error('Logout API call failed:', response.statusText);
        }
    } catch (error) {
        console.error('Error calling logout API:', error);
    }

    // Clear client-side state
    setCurrentUser(null);
    ndk.activeUser = undefined;
    // Properly delete the client-side cookie by setting max-age=0 with the same path
    document.cookie = "keycastUserPubkey=; max-age=0; path=/; SameSite=Lax; Secure";
    toast.success("Signed out");
    goto("/");
}
