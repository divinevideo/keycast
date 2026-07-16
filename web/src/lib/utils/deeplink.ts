/**
 * Extract the auto-run search query from a page's URL params.
 *
 * Returns the trimmed `q` value, or null when it is absent or empty. This lets a
 * deeplink like `/support-admin?q=<pubkey>` run the lookup on load, while a bare
 * visit (or an empty `q`) does nothing.
 */
export function deeplinkQuery(params: URLSearchParams): string | null {
    const q = params.get("q")?.trim();
    return q ? q : null;
}
