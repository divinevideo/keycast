import { browser } from "$app/environment";
import type { NDKCacheAdapter } from "@nostr-dev-kit/ndk";
import NDK from "@nostr-dev-kit/ndk";
import NDKCacheAdapterDexie from "@nostr-dev-kit/ndk-cache-dexie";
import { getEnvVar } from "$lib/utils/env";

let cacheAdapter: NDKCacheAdapter | undefined = undefined;

if (browser) {
    cacheAdapter = new NDKCacheAdapterDexie({ dbName: "keycast" });
}

// Get relay URLs from runtime config
// Returns empty array if not configured (no external connections)
function getRelayUrls(envVar: 'VITE_NDK_EXPLICIT_RELAYS' | 'VITE_NDK_BUNKER_RELAYS'): string[] {
    const configRelays = getEnvVar(envVar);
    if (configRelays) {
        return configRelays.split(',').map(r => r.trim()).filter(r => r.length > 0);
    }
    // No relays configured - no external connections
    return [];
}

// Get explicit relay URLs (for reading/subscribing)
// Must be explicitly configured - no hardcoded defaults
const explicitRelayUrls = getRelayUrls('VITE_NDK_EXPLICIT_RELAYS');

// Keycast is a read-only signing service - it doesn't publish events to relays
// Events are signed and returned to clients, who publish them themselves
export const ndkStore = new NDK({
    explicitRelayUrls,
    enableOutboxModel: false, // Read-only - keycast doesn't publish events
    autoConnectUserRelays: true,
    autoFetchUserMutelist: true,
    cacheAdapter,
    clientName: "keycast",
});

// Only connect if explicit relays are configured
if (explicitRelayUrls.length > 0) {
    ndkStore.connect().then(() => console.log("NDK Connected"));
} else {
    console.warn("NDK: No explicit relays configured (VITE_NDK_EXPLICIT_RELAYS). NDK will not connect to external relays.");
}

// Create a singleton instance that is the default export
const ndk = $state(ndkStore);

// Get bunker relay URLs (for NIP-46 bunker communication)
// Must be explicitly configured - no hardcoded defaults
const bunkerRelayUrls = getRelayUrls('VITE_NDK_BUNKER_RELAYS');

export const bunkerNDKStore = new NDK({
    explicitRelayUrls: bunkerRelayUrls,
    enableOutboxModel: false, // Read-only
});

// Only connect if bunker relays are configured
if (bunkerRelayUrls.length > 0) {
    bunkerNDKStore.connect().then(() => console.log("Bunker NDK Connected"));
} else {
    console.warn("NDK: No bunker relays configured (VITE_NDK_BUNKER_RELAYS). Bunker NDK will not connect to external relays.");
}

export const bunkerNdk = $state(bunkerNDKStore);
export default ndk;
