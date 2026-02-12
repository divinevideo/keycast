<script lang="ts">
import { goto } from "$app/navigation";
import { page } from "$app/stores";
import { getCurrentUser } from "$lib/current_user.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import type { User } from "$lib/types";
import { pubkeyFromNpubOrHex } from "$lib/utils/nostr";
import { toast } from "svelte-hot-french-toast";

const { id } = $page.params;

const api = new KeycastApi();
const user = $derived(getCurrentUser());

let pubkeyOrNpub: string = $state("");
let role: "Admin" | "Member" = $state("Member");
let errorMessage: string | null = $state(null);

async function addTeammate() {
    if (!user?.pubkey) return;
    if (!pubkeyOrNpub) {
        errorMessage = "You must provide a public key or npub.";
        return;
    }

    let resolvedPubkey: string;
    try {
        resolvedPubkey = pubkeyFromNpubOrHex(pubkeyOrNpub);
    } catch {
        errorMessage = "Invalid public key or npub.";
        return;
    }

    api.post<User>(
        `/teams/${id}/users`,
        {
            user_pubkey: resolvedPubkey,
            role,
        },
    )
        .then((_newUser) => {
            toast.success("Teammate added successfully");
            goto(`/teams/${id}`);
        })
        .catch((error) => {
            toast.error("Failed to add teammate");
            errorMessage = error.message;
        });
}
</script>

<h1 class="page-header">Add Teammate</h1>

<form onsubmit={() => addTeammate()}>
    <div class="form-group">
        <label for="pubkey">Public key or npub</label>
        <input type="text" bind:value={pubkeyOrNpub} placeholder="npub1..." />
        {#if errorMessage}
            <span class="input-error">{errorMessage}</span>
        {/if}
    </div>
    <div class="form-group">
        <label for="role">Role</label>
        <select bind:value={role}>
            <option value="Member">Member</option>
            <option value="Admin">Admin</option>
        </select>
    </div>
    <button type="submit" class="button button-primary">Add Teammate</button>
</form>
