/**
 * Runtime environment variable accessor
 * Reads from window.__ENV__ (injected at runtime) with fallback to import.meta.env (build-time)
 */

declare global {
    interface Window {
        __ENV__?: {
            VITE_DOMAIN?: string;
            ALLOWED_PUBKEYS?: string;
            SHOW_TEAMS_FUNCTIONALITY?: string;
        };
    }
}

/**
 * Get a runtime environment variable with fallback to build-time value
 */
export function getEnvVar(key: 'VITE_DOMAIN' | 'ALLOWED_PUBKEYS' | 'SHOW_TEAMS_FUNCTIONALITY'): string | undefined {
    // Check runtime injection first (from window.__ENV__)
    if (typeof window !== 'undefined' && window.__ENV__?.[key]) {
        return window.__ENV__[key];
    }

    // Fallback to build-time value (import.meta.env)
    // Vite only exposes VITE_-prefixed vars, so check both forms
    return import.meta.env[key] || import.meta.env[`VITE_${key}`];
}

/**
 * Get VITE_DOMAIN with default fallback
 */
export function getViteDomain(defaultValue: string = 'http://localhost:3000'): string {
    return getEnvVar('VITE_DOMAIN') || defaultValue;
}

/**
 * Get ALLOWED_PUBKEYS (comma-separated string)
 */
export function getAllowedPubkeys(): string {
    return getEnvVar('ALLOWED_PUBKEYS') || '';
}

/**
 * Whether teams functionality is enabled (requires SHOW_TEAMS_FUNCTIONALITY env var)
 */
export function isTeamsEnabled(): boolean {
    const val = getEnvVar('SHOW_TEAMS_FUNCTIONALITY');
    return val === 'true' || val === '1';
}
