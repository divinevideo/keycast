import { browser } from "$app/environment";
import { goto } from "$app/navigation";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import toast from "svelte-hot-french-toast";
import { getViteDomain, getAllowedPubkeys, isTeamsEnabled } from "$lib/utils/env";

export enum SigninMethod {
    Nip07 = "nip07",
    NostrLogin = "nostr-login",
    Cloudflare = "cloudflare",
}

function isAllowedPubkey(pubkey: string) {
    const allowedPubkeys = getAllowedPubkeys();
    return allowedPubkeys && allowedPubkeys.includes(pubkey);
}

export async function signin(
    method?: SigninMethod,
): Promise<string | null> {
    let pubkey: string | null = null;
    if (method === SigninMethod.Nip07) {
        pubkey = await nip07Login();
    }
    if (pubkey) {
        const alreadySignedIn = !!getCurrentUser();
        if (!alreadySignedIn) {
            toast.success("Signed in successfully");
        }
        const dest = method === SigninMethod.Nip07 ? "/" : (isTeamsEnabled() ? "/teams" : "/");
        goto(dest);
    }
    return pubkey;
}

async function nip07Login(): Promise<string | null> {
    if (!browser || !window.nostr) {
        toast.error("NIP-07 extension not found");
        return null;
    }

    try {
        const pubkey = await window.nostr.getPublicKey();

        if (!isAllowedPubkey(pubkey)) {
            toast.error("Your pubkey is not authorized for admin access");
            return null;
        }

        const apiBase = getViteDomain();
        const url = `${apiBase}/api/auth/login`;

        const eventTemplate = {
            kind: 27235,
            content: "",
            created_at: Math.floor(Date.now() / 1000),
            tags: [
                ["u", url],
                ["method", "POST"],
            ],
        };

        const signedEvent = await window.nostr.signEvent(eventTemplate);

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Nostr ${btoa(JSON.stringify(signedEvent))}`,
                'Origin': window.location.origin,
            },
            credentials: 'include',
        });

        if (response.ok) {
            const data = await response.json();
            setCurrentUser(data.pubkey, 'nip07');
            document.cookie = `keycastUserPubkey=${data.pubkey}; max-age=1209600; SameSite=Lax; Secure; path=/`;
            return data.pubkey;
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

/** Check if CF_Authorization cookie is present (set by Cloudflare Access) */
export function hasCfAccessCookie(): boolean {
    if (typeof document === 'undefined') return false;
    return document.cookie.split(';').some(c => c.trim().startsWith('CF_Authorization='));
}

/** Extract CF_Authorization cookie value */
function getCfAccessToken(): string | null {
    if (typeof document === 'undefined') return null;
    for (const cookie of document.cookie.split(';')) {
        const trimmed = cookie.trim();
        if (trimmed.startsWith('CF_Authorization=')) {
            return trimmed.substring('CF_Authorization='.length);
        }
    }
    return null;
}

/** Login via Cloudflare Access JWT */
export async function cloudflareLogin(): Promise<string | null> {
    const token = getCfAccessToken();
    if (!token) return null;

    try {
        const apiBase = getViteDomain();
        const response = await fetch(`${apiBase}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Cf-Access-Jwt-Assertion': token,
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: '{}',
        });

        if (response.ok) {
            const data = await response.json();
            setCurrentUser(data.pubkey, 'cloudflare');
            return data.pubkey;
        } else {
            console.warn('CF Access login failed:', response.status);
            return null;
        }
    } catch (error) {
        console.error('CF Access login error:', error);
        return null;
    }
}

export async function signout() {
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

    setCurrentUser(null);
    document.cookie = "keycastUserPubkey=; max-age=0; path=/; SameSite=Lax; Secure";
    toast.success("Signed out");
    goto("/");
}
