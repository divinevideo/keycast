/**
 * Runtime environment variable accessor
 * Reads from window.__ENV__ (injected at runtime) with fallback to import.meta.env (build-time)
 */

declare global {
    interface Window {
        __ENV__?: {
            VITE_DOMAIN?: string;
            VITE_ALLOWED_PUBKEYS?: string;
            VITE_NDK_EXPLICIT_RELAYS?: string;
            VITE_NDK_BUNKER_RELAYS?: string;
        };
    }
}

/**
 * Get a runtime environment variable with fallback to build-time value
 */
export function getEnvVar(key: 'VITE_DOMAIN' | 'VITE_ALLOWED_PUBKEYS' | 'VITE_NDK_EXPLICIT_RELAYS' | 'VITE_NDK_BUNKER_RELAYS'): string | undefined {
    // Check runtime injection first (from window.__ENV__)
    if (typeof window !== 'undefined' && window.__ENV__?.[key]) {
        return window.__ENV__[key];
    }
    
    // Fallback to build-time value (import.meta.env)
    return import.meta.env[key];
}

/**
 * Get VITE_DOMAIN with default fallback
 */
export function getViteDomain(defaultValue: string = 'http://localhost:3000'): string {
    return getEnvVar('VITE_DOMAIN') || defaultValue;
}

/**
 * Get VITE_ALLOWED_PUBKEYS (comma-separated string)
 */
export function getViteAllowedPubkeys(): string {
    return getEnvVar('VITE_ALLOWED_PUBKEYS') || '';
}
