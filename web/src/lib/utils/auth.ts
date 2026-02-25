import { browser } from "$app/environment";
import { goto } from "$app/navigation";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import toast from "svelte-hot-french-toast";
import { getViteDomain, isTeamsEnabled } from "$lib/utils/env";

export enum SigninMethod {
    Nip07 = "nip07",
    NostrLogin = "nostr-login",
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
        let dest = isTeamsEnabled() ? "/teams" : "/";
        if (method === SigninMethod.Nip07) {
            // Check actual admin role to redirect to the right page
            try {
                const statusRes = await fetch(`${getViteDomain()}/api/admin/status`, { credentials: 'include' });
                if (statusRes.ok) {
                    const status = await statusRes.json();
                    dest = status.role === "full" ? "/admin" : "/support-admin";
                }
            } catch {
                dest = "/admin";
            }
        }
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
    toast.success("Signed out");
    goto("/");
}
