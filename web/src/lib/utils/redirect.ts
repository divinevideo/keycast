// Sentinel origin used to resolve redirect targets. Only a genuine same-origin
// relative path keeps this origin after URL parsing.
const SENTINEL_ORIGIN = "http://localhost";

/**
 * Validate a post-login redirect target.
 *
 * Only same-origin relative paths are allowed: the value must start with a single `/`,
 * and resolving it against a sentinel origin must not change that origin. This rejects
 * protocol-relative (`//host`), backslash (`/\host`), and control-character tricks
 * (`/\t/host`, which browsers strip to `//host`) — all open-redirect vectors. The path,
 * query, and hash are preserved for valid values. Anything invalid falls back to `/`.
 */
export function safeRedirectPath(redirect: string | null | undefined): string {
    if (!redirect || !redirect.startsWith("/")) return "/";
    try {
        const url = new URL(redirect, SENTINEL_ORIGIN);
        if (url.origin !== SENTINEL_ORIGIN) return "/";
        return url.pathname + url.search + url.hash;
    } catch {
        return "/";
    }
}

/**
 * Resolve a post-authentication destination. An explicit, same-origin `redirect`
 * target (e.g. the page the user was bounced off when their session expired) takes
 * precedence over the caller's computed `fallback`. Anything missing or unsafe yields
 * the fallback.
 */
export function resolvePostAuthDest(
    requested: string | null | undefined,
    fallback: string,
): string {
    const safe = safeRedirectPath(requested);
    return safe === "/" ? fallback : safe;
}
