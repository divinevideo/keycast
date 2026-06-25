import { browser } from "$app/environment";
import { goto } from "$app/navigation";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import { ApiError } from "$lib/keycast_api.svelte";
import { resolvePostAuthDest } from "$lib/utils/redirect";
import toast from "svelte-hot-french-toast";
import { getViteDomain, isTeamsEnabled } from "$lib/utils/env";

export enum SigninMethod {
    Nip07 = "nip07",
    NostrLogin = "nostr-login",
}

interface SignoutOptions {
    redirectTo?: string | null;
    showToast?: boolean;
}

// Guards against a burst of simultaneous 401s (e.g. several parallel requests failing
// at once) firing multiple toasts and navigations. Cleared once the login navigation
// settles, so a later session expiry is handled again.
let redirecting = false;

/**
 * If `err` is an authentication 401 (expired/missing session), clear stale client
 * auth state, surface a session-expired message, and redirect to /login with a return
 * path. Returns true when it handled the error so callers can early-return instead of
 * rendering the raw internal auth message.
 *
 * Only fires on 401 — a 403 ("logged in but not authorized") and all other errors are
 * left for the caller to handle, preserving the not-logged-in vs forbidden distinction.
 */
export function redirectToLoginOnAuthError(
    err: unknown,
    returnPath?: string,
): boolean {
    if (!(err instanceof ApiError) || err.status !== 401) {
        return false;
    }

    // Report the 401 as handled to every caller so they all early-return, but only run
    // the redirect side effects for the first 401 in a burst.
    if (redirecting) {
        return true;
    }
    redirecting = true;

    // Drop the lingering client-side pubkey cookie/state so the UI no longer believes
    // it is signed in.
    setCurrentUser(null);

    const path =
        returnPath ?? (browser ? window.location.pathname + window.location.search : "/");
    toast.error("Your session has expired. Please sign in again.");
    goto(`/login?redirect=${encodeURIComponent(path)}`, { replaceState: true }).finally(() => {
        redirecting = false;
    });
    // Safety net: a navigation promise that never settles must not latch `redirecting`
    // forever and silently swallow every later 401.
    setTimeout(() => {
        redirecting = false;
    }, 10_000);
    return true;
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
        // Sign-in's default destination is role-aware on purpose: nip07 sign-in lands
        // admins on their console (below), while password login (login/+page.svelte)
        // defaults to "/". An explicit ?redirect= overrides either. This divergence is
        // intentional, not an oversight.
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
        // An explicit, same-origin `redirect` (e.g. the page the user was bounced off
        // when their session expired) takes precedence over the computed default.
        const requested = browser
            ? new URLSearchParams(window.location.search).get("redirect")
            : null;
        goto(resolvePostAuthDest(requested, dest));
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

export async function signout(options: SignoutOptions = {}) {
    const { redirectTo = "/", showToast = true } = options;

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
    if (showToast) {
        toast.success("Signed out");
    }
    if (redirectTo) {
        goto(redirectTo);
    }
}
