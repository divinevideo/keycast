<script lang="ts">
import { page } from "$app/stores";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import { SigninMethod, signin, signout } from "$lib/utils/auth";
import { SignIn, SignOut } from "phosphor-svelte";
import { onMount } from "svelte";
import { BRAND } from "$lib/brand";
import { isTeamsEnabled } from "$lib/utils/env";

const user = $derived(getCurrentUser());
const activePage = $derived($page.url.pathname);

// Check for cookie-based authentication on mount
onMount(async () => {
	if (!user) {
		try {
			const response = await fetch('/api/oauth/auth-status', {
				credentials: 'include'
			});
			if (response.ok) {
				const data = await response.json();
				if (data.authenticated && data.pubkey) {
					const savedMethod = localStorage.getItem('keycast_auth_method') as 'nip07' | 'cookie' || 'cookie';
					setCurrentUser(data.pubkey, savedMethod);
				}
			}
		} catch (err) {
			console.warn('Failed to check auth status:', err);
		}
	}
});
</script>


<div class="container flex flex-row items-center justify-between mb-8">
	<a href="/" class="flex flex-col items-start gap-0 group transition-opacity hover:opacity-85">
		<img src="/divine-logo.svg" alt="{BRAND.shortName}" class="h-[22px]" />
		<span class="text-[10px] font-medium tracking-[3px] uppercase text-[var(--color-divine-green)] opacity-60">Login</span>
	</a>

    <nav class="flex flex-row items-center justify-start gap-4">
        {#if user}
            {#if activePage !== '/'}
                <a class="nav-link bordered" href="/">Dashboard</a>
            {/if}
            {#if isTeamsEnabled()}
            <a class="nav-link {activePage === '/teams' ? 'active' : ''} bordered" href="/teams">Teams</a>
            {/if}
            <button
                onclick={() => signout()}
                class="button button-secondary button-icon"
                role="menuitem"
                tabindex="-1"
                id="user-menu-item-1"
            >
                <SignOut size="20" />
                Sign out
            </button>
        {:else}
            <button
                onclick={() => signin(SigninMethod.Nip07)}
                class="button button-primary button-icon"
            >
                <SignIn size="20" />
                Sign in
            </button>
        {/if}
    </nav>
</div>
