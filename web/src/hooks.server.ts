import type { Handle } from "@sveltejs/kit";
import { redirect } from "@sveltejs/kit";

const protectedRoutes: string[] = ["/teams", "/keys", "/admin", "/support-admin"];

export const handle: Handle = async ({ event, resolve }) => {
    // Gate protected routes on `keycast_session` only — that is the cookie the API
    // actually accepts. `keycastUserPubkey` is a client-set convenience cookie with a
    // much longer lifetime (14d vs the 24h session), so trusting it for gating leaves
    // users on protected pages whose cookie-authenticated API calls then fail with raw
    // 401 auth errors. Redirect to /login with a return path so they land back here.
    const hasSession = event.cookies.get("keycast_session");
    if (!hasSession && protectedRoutes.includes(event.url.pathname)) {
        const redirectTarget = encodeURIComponent(event.url.pathname + event.url.search);
        throw redirect(303, `/login?redirect=${redirectTarget}`);
    }

    return resolve(event);
};
