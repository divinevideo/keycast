<script lang="ts">
import { getCurrentUser } from "$lib/current_user.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import ndk from "$lib/ndk.svelte";
import type { AuthorizationWithRelations } from "$lib/types";
import { formattedDateTime } from "$lib/utils/dates";
import { NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { Check, Copy, Trash } from "phosphor-svelte";
import { toast } from "svelte-hot-french-toast";

let { authorization, teamId, keyPubkey, onDelete }: {
    authorization: AuthorizationWithRelations;
    teamId: string;
    keyPubkey: string;
    onDelete?: () => void;
} = $props();

const api = new KeycastApi();
const user = $derived(getCurrentUser()?.user);
let copyConnectionSuccess = $state(false);
let isDeleting = $state(false);

function copyConnectionString(authorization: AuthorizationWithRelations) {
    navigator.clipboard.writeText(authorization.bunker_connection_string);
    toast.success("Connection string copied to clipboard");
    copyConnectionSuccess = true;
    setTimeout(() => {
        copyConnectionSuccess = false;
    }, 2000);
}

async function deleteAuthorization() {
    if (!user?.pubkey) return;
    if (!confirm("Are you sure you want to delete this authorization? This cannot be undone.")) return;

    isDeleting = true;
    const authMethod = getCurrentUser()?.authMethod;
    let authHeaders: Record<string, string> = {};

    try {
        if (authMethod === 'nip07') {
            const authEvent = await api.buildUnsignedAuthEvent(
                `/teams/${teamId}/keys/${keyPubkey}/authorizations/${authorization.authorization.id}`,
                "DELETE",
                user.pubkey,
            );
            if (!ndk.signer) {
                ndk.signer = new NDKNip07Signer();
            }
            await authEvent?.sign();
            authHeaders.Authorization = `Nostr ${btoa(JSON.stringify(authEvent))}`;
        }

        await api.delete(`/teams/${teamId}/keys/${keyPubkey}/authorizations/${authorization.authorization.id}`, {
            headers: authHeaders,
        });
        toast.success("Authorization deleted");
        onDelete?.();
    } catch (error) {
        toast.error("Failed to delete authorization");
    } finally {
        isDeleting = false;
    }
}
</script>

<div class="card">
    <div class="flex justify-between items-start gap-2">
        <h3 class="font-mono text-sm truncate flex-1">{authorization.authorization.secret}</h3>
        <button
            onclick={deleteAuthorization}
            disabled={isDeleting}
            class="text-gray-400 hover:text-red-500 transition-colors p-1"
            title="Delete authorization"
        >
            <Trash size="18" />
        </button>
    </div>
    <button onclick={() => copyConnectionString(authorization)} class="flex flex-row gap-2 items-center justify-center button button-primary button-icon {copyConnectionSuccess ? 'bg-green-600! text-white! ring-green-600!' : ''} transition-all duration-200">
        {#if copyConnectionSuccess}
            <Check size="20" />
            Copied!
        {:else}
            <Copy size="20" />
            Copy connection string
        {/if}
    </button>
    <div class="grid grid-cols-[auto_1fr] gap-y-1 gap-x-2 text-xs text-gray-400">
        <span class="whitespace-nowrap">Redemptions:</span>
        <span>{authorization.users.length} / {authorization.authorization.max_uses || "∞"}</span>
        <span class="whitespace-nowrap">Expiration:</span>
        <span>{formattedDateTime(new Date(authorization.authorization.expires_at)) || "None"}</span>
        <span class="whitespace-nowrap">Relays:</span>
        <span>{authorization.authorization.relays.join(", ")}</span>
        <span class="whitespace-nowrap">Policy:</span>
        <span>{authorization.policy.name}</span>
    </div>
</div>
