/**
 * Validate a post-login redirect target.
 *
 * Only same-origin absolute paths are allowed: the value must start with a single `/`.
 * Protocol-relative (`//host`) and backslash-trick (`/\host`) values are rejected
 * because browsers resolve them to a different origin, which would be an open redirect.
 * The query string and hash are preserved for valid paths. Anything invalid falls back
 * to `/`.
 */
export function safeRedirectPath(redirect: string | null | undefined): string {
    if (!redirect || !redirect.startsWith("/")) return "/";
    // Reject `//host` and `/\host` — both resolve off-origin in browsers.
    if (redirect.startsWith("//") || redirect.startsWith("/\\")) return "/";
    return redirect;
}
