<script lang="ts">
import { page } from "$app/stores";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import ndk from "$lib/ndk.svelte";
import { SigninMethod, signin, signout } from "$lib/utils/auth";
import { Key, SignIn, SignOut } from "phosphor-svelte";
import { onMount } from "svelte";

const user = $derived(getCurrentUser()?.user);
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


<div class="container flex flex-row items-center justify-between mb-12">
	<a href="/" class="flex flex-col items-start justify-start">
		<h1 class="text-3xl font-bold flex flex-row gap-1 items-center">
            <Key size="32" weight="fill" />
            Keycast
        </h1>
		<p class="hidden md:block text-gray-400">Secure remote signing for your team</p>
	</a>

    <nav class="flex flex-row items-center justify-start gap-4">
        {#if user}
            {#if activePage !== '/'}
                <a class="nav-link bordered" href="/">Dashboard</a>
            {/if}
            <a class="nav-link {activePage === '/teams' ? 'active' : ''} bordered" href="/teams">Teams</a>
            <a class="nav-link {activePage === '/settings/connected-apps' ? 'active' : ''} bordered" href="/settings/connected-apps">Connected Apps</a>
            <button
                onclick={() => signout(ndk)}
                ontouchend={() => signout(ndk)}
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
                onclick={() => signin(ndk, undefined, SigninMethod.Nip07)}
                class="button button-primary button-icon"
            >
                <SignIn size="20" />
                Sign in
            </button>
        {/if}
    </nav>
</div>
