import type { Handle } from "@sveltejs/kit";
import { redirect } from "@sveltejs/kit";

// Key pages live under /teams/[id]/keys, so the /teams prefix already covers them —
// there is no top-level /keys route.
const protectedRoutes: string[] = ["/teams", "/admin", "/support-admin"];

export const handle: Handle = async ({ event, resolve }) => {
    // Gate protected routes on `keycast_session` only — that is the cookie the API
    // actually accepts. `keycastUserPubkey` is a client-set convenience cookie with a
    // much longer lifetime (14d vs the 24h session), so trusting it for gating leaves
    // users on protected pages whose cookie-authenticated API calls then fail with raw
    // 401 auth errors. Redirect to /login with a return path so they land back here.
    const { pathname } = event.url;
    // Prefix match so nested routes (e.g. /teams/123, /admin/registered-clients) are
    // gated too, not just the exact base paths.
    const isProtected = protectedRoutes.some((route) => pathname === route || pathname.startsWith(`${route}/`));
    const hasSession = event.cookies.get("keycast_session");
    if (!hasSession && isProtected) {
        const redirectTarget = encodeURIComponent(pathname + event.url.search);
        throw redirect(303, `/login?redirect=${redirectTarget}`);
    }

    return resolve(event);
};
