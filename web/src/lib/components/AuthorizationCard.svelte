<script lang="ts">
import { getCurrentUser } from "$lib/current_user.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import type { AuthorizationWithRelations } from "$lib/types";
import { formattedDateTime } from "$lib/utils/dates";
import { Check, Copy, Trash, Link, LinkBreak } from "phosphor-svelte";
import { toast } from "svelte-hot-french-toast";

let { authorization, teamId, keyPubkey, onDelete }: {
    authorization: AuthorizationWithRelations;
    teamId: string;
    keyPubkey: string;
    onDelete?: () => void;
} = $props();

const api = new KeycastApi();
const user = $derived(getCurrentUser());
let copyConnectionSuccess = $state(false);
let isDeleting = $state(false);

const isConnected = $derived(!!authorization.authorization.connected_client_pubkey);
const truncatedClientPubkey = $derived(
    authorization.authorization.connected_client_pubkey
        ? `${authorization.authorization.connected_client_pubkey.slice(0, 8)}...${authorization.authorization.connected_client_pubkey.slice(-8)}`
        : null
);

function copyConnectionString(authorization: AuthorizationWithRelations) {
    if (!authorization.bunker_connection_string) {
        toast.error("Connection string only available at creation time");
        return;
    }
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

    try {
        await api.delete(`/teams/${teamId}/keys/${keyPubkey}/authorizations/${authorization.authorization.id}`);
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
        <div class="flex flex-col gap-1">
            {#if authorization.authorization.label}
                <span class="font-semibold text-white">{authorization.authorization.label}</span>
            {/if}
            <div class="flex items-center gap-2">
                {#if isConnected}
                    <Link size="18" class="text-green-500" />
                    <span class="text-sm text-green-500">Connected</span>
                {:else}
                    <LinkBreak size="18" class="text-gray-400" />
                    <span class="text-sm text-gray-400">Pending</span>
                {/if}
            </div>
        </div>
        <button
            onclick={deleteAuthorization}
            disabled={isDeleting}
            class="text-gray-400 hover:text-red-500 transition-colors p-1"
            title="Delete authorization"
        >
            <Trash size="18" />
        </button>
    </div>
    {#if authorization.bunker_connection_string}
        <button onclick={() => copyConnectionString(authorization)} class="flex flex-row gap-2 items-center justify-center button button-primary button-icon {copyConnectionSuccess ? 'bg-green-600! text-white! ring-green-600!' : ''} transition-all duration-200">
            {#if copyConnectionSuccess}
                <Check size="20" />
                Copied!
            {:else}
                <Copy size="20" />
                Copy connection string
            {/if}
        </button>
    {/if}
    <div class="grid grid-cols-[auto_1fr] gap-y-1 gap-x-2 text-xs text-gray-400">
        {#if isConnected && truncatedClientPubkey}
            <span class="whitespace-nowrap">Client:</span>
            <span class="font-mono">{truncatedClientPubkey}</span>
            <span class="whitespace-nowrap">Connected:</span>
            <span>{formattedDateTime(new Date(authorization.authorization.connected_at!))}</span>
        {/if}
        <span class="whitespace-nowrap">Expiration:</span>
        <span>{authorization.authorization.expires_at ? formattedDateTime(new Date(authorization.authorization.expires_at)) : "None"}</span>
        <span class="whitespace-nowrap">Relays:</span>
        <span>{authorization.authorization.relays.join(", ")}</span>
        <span class="whitespace-nowrap">Policy:</span>
        <span>{authorization.policy.name}</span>
    </div>
</div>
