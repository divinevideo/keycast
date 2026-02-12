<script lang="ts">
import { goto } from "$app/navigation";
import { page } from "$app/stores";
import PageSection from "$lib/components/PageSection.svelte";
import { getCurrentUser } from "$lib/current_user.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import type {
    PolicyWithPermissions,
    StoredKey,
    Team,
    TeamWithRelations,
} from "$lib/types";
import { readablePermissionConfig } from "$lib/utils/permissions";
import { toTitleCase } from "$lib/utils/strings";
import { CaretRight, X, Copy, Check, Warning } from "phosphor-svelte";
import { toast } from "svelte-hot-french-toast";

const { id, pubkey } = $page.params;

const api = new KeycastApi();
const user = $derived(getCurrentUser());
let isLoading = $state(true);
let hasFetched = $state(false);

let maxUses: number | null = $state(0);
let expiresAt: Date | null = $state(null);
let relaysString: string = $state(
    "wss://relay.nsecbunker.com, wss://relay.nsec.app",
);
let label: string = $state("");

let relays: string[] = $derived(
    relaysString.split(",").map((relay) => relay.trim()),
);

let teamWithRelations: TeamWithRelations | null = $state(null);
let team: Team | null = $state(null);
let policies: PolicyWithPermissions[] | null = $state(null);
let key: StoredKey | null | undefined = $state(null);
let selectedPolicyId: number | null = $state(null);

// Success modal state
let showSuccessModal = $state(false);
let createdBunkerUrl: string | null = $state(null);
let bunkerUrlCopied = $state(false);

let readyToSubmit = $derived(
    maxUses !== null && relaysString && selectedPolicyId,
);

$effect(() => {
    if (user?.pubkey && !hasFetched) {
        hasFetched = true;
        api.get(`/teams/${id}`)
            .then((teamResponse) => {
                teamWithRelations =
                    teamResponse as TeamWithRelations;
                team = teamWithRelations.team;
                key = teamWithRelations.stored_keys.find(
                    (key) => key.pubkey === pubkey,
                );
                policies = teamWithRelations.policies;
            })
            .finally(() => {
                isLoading = false;
            });
    }
});

async function createAuthorization() {
    if (!user?.pubkey) {
        toast.error("You must be logged in to create an authorization");
        return;
    }

    if (!selectedPolicyId) {
        toast.error("You must select a policy");
        return;
    }

    if (!relaysString) {
        toast.error("You must enter at least one relay");
        return;
    }

    const request = {
        max_uses: maxUses === 0 ? null : maxUses,
        expires_at: expiresAt
            ? Math.floor(new Date(expiresAt).getTime() / 1000)
            : null,
        relays: relays,
        policy_id: selectedPolicyId,
        label: label.trim() || null,
    };

    api.post(`/teams/${id}/keys/${pubkey}/authorizations`, request)
        .then((response) => {
            // Show success modal with bunker URL - this is the ONLY time the URL is available
            const authResponse = response as { bunker_url: string };
            createdBunkerUrl = authResponse.bunker_url;
            showSuccessModal = true;
        })
        .catch((error) => {
            toast.error("Failed to create authorization");
            toast.error(`Failed to create authorization: ${error.message}`);
        });
}

function copyBunkerUrl() {
    if (createdBunkerUrl) {
        navigator.clipboard.writeText(createdBunkerUrl);
        bunkerUrlCopied = true;
        toast.success("Bunker URL copied to clipboard");
        setTimeout(() => {
            bunkerUrlCopied = false;
        }, 2000);
    }
}

function closeSuccessModal() {
    showSuccessModal = false;
    createdBunkerUrl = null;
    goto(`/teams/${id}/keys/${pubkey}`);
}
</script>

<h1 class="page-header flex flex-row gap-1 items-center">
    <a href={`/teams/${id}`} class="bordered">{team?.name}</a>
    <CaretRight size="20" class="text-gray-500" />
    <a href={`/teams/${id}/keys/${pubkey}`} class="bordered">{key?.name}</a>
    <CaretRight size="20" class="text-gray-500" />
    Add Authorization
</h1>

<PageSection title="Authorization">
    <form onsubmit={() => createAuthorization()}>
        <div class="form-group">
            <label for="label">Label (Optional - e.g., person's name)</label>
            <input type="text" bind:value={label} placeholder="e.g., John Doe" />
        </div>

        <div class="form-group">
            <label for="maxUses">Maximum uses (Zero for unlimited)</label>
            <input type="number" bind:value={maxUses} />
        </div>

        <div class="form-group">
            <label for="relays">Relays (Comma separated)</label>
            <input type="text" bind:value={relaysString} />
        </div>

        <div class="form-group">
            <label for="expiresAt">Expiration date (Leave blank for no expiration)</label>
            <div class="flex flex-row gap-2 items-center">
                <input type="datetime-local" bind:value={expiresAt} />
                {#if expiresAt}
                    <button type="button" class="clear-button" onclick={() => expiresAt = null}>
                        <X weight="light" size={16} />
                    </button>
                {/if}
            </div>
        </div>
    </form>
</PageSection>

    <PageSection title="Policies">
        <div class="flex flex-col gap-4">
            {#if !policies || policies.length === 0}
                <p class="text-gray-500">No policies found</p>
            {:else}
                <div class="card-grid">
                    {#each policies as policy}
                        <!-- svelte-ignore a11y_click_events_have_key_events -->
                        <div
                            class="card hover-card {selectedPolicyId === policy.policy.id ? 'ring-2! ring-indigo-500!' : ''}"
                            onclick={() => selectedPolicyId = policy.policy.id}
                            role="button"
                            tabindex="0"
                        >
                            <h3 class="text-lg font-semibold">{policy.policy.name}</h3>
                            <ul class="">
                                {#each policy.permissions as permission}
                                    <li class="text-sm text-gray-300">{toTitleCase(permission.identifier)}
                                        <ul class="list-disc list-inside ml-2">
                                            {#each readablePermissionConfig(permission) as config}
                                                <li class="text-xs text-gray-400">{config}</li>
                                            {/each}
                                        </ul>
                                    </li>
                                {/each}
                            </ul>
                        </div>
                    {/each}
                </div>
            {/if}
            <a href={`/teams/${id}/policies/new`} class="button self-start button-primary my-0!">Add Policy</a>
        </div>
    </PageSection>

    <button onclick={createAuthorization} class="button button-primary" disabled={!readyToSubmit}>Add Authorization</button>

{#if showSuccessModal}
    <!-- Success Modal -->
    <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full mx-4 shadow-xl">
            <h2 class="text-xl font-bold text-green-400 mb-4">Authorization Created</h2>

            <div class="bg-yellow-900/50 border border-yellow-600 rounded-lg p-4 mb-4">
                <div class="flex items-start gap-2">
                    <Warning size="20" class="text-yellow-500 flex-shrink-0 mt-0.5" />
                    <div class="text-sm text-yellow-200">
                        <strong>Important:</strong> This bunker URL can only be shown once.
                        Copy it now and share it with the team member who will use this authorization.
                        It cannot be retrieved later.
                    </div>
                </div>
            </div>

            <div class="mb-4">
                <div class="block text-sm text-gray-400 mb-2">Bunker URL</div>
                <div class="bg-gray-900 rounded p-3 font-mono text-sm break-all text-gray-300">
                    {createdBunkerUrl}
                </div>
            </div>

            <div class="flex gap-3">
                <button
                    onclick={copyBunkerUrl}
                    class="button button-primary flex items-center gap-2 flex-1 {bunkerUrlCopied ? 'bg-green-600!' : ''}"
                >
                    {#if bunkerUrlCopied}
                        <Check size="20" />
                        Copied!
                    {:else}
                        <Copy size="20" />
                        Copy Bunker URL
                    {/if}
                </button>
                <button
                    onclick={closeSuccessModal}
                    class="button flex-1"
                >
                    Done
                </button>
            </div>
        </div>
    </div>
{/if}
