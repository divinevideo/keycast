<script lang="ts">
import "../app.css";
import Header from "$lib/components/Header.svelte";
import VerificationBanner from "$lib/components/VerificationBanner.svelte";
import BetaBanner from "$lib/components/BetaBanner.svelte";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import { fetchAccountStatus, clearAccountStatus } from "$lib/account_status.svelte";
import { initApi } from "$lib/keycast_api.svelte";
import { Toaster } from "svelte-hot-french-toast";
import { page } from "$app/stores";

let { data, children }: { data?: { keycastCookie?: string }, children: any } = $props();
let keycastCookie = $derived(data?.keycastCookie);
initApi();

$effect(() => {
    if (keycastCookie && getCurrentUser()?.user?.pubkey !== keycastCookie) {
        const savedMethod = (localStorage.getItem('keycast_auth_method') as 'nip07' | 'cookie') || 'cookie';
        setCurrentUser(keycastCookie, savedMethod);
    }
});

// Clear account status when user logs out
// Note: fetchAccountStatus() is called by +page.svelte after verifying auth
$effect(() => {
    const currentUser = getCurrentUser();
    if (!currentUser) {
        clearAccountStatus();
    }
});

// Hide header on auth pages (full-page experience)
// Show header on homepage if authenticated (dashboard mode)
const authOnlyPaths = ['/login', '/register', '/verify-email'];
const isAuthPage = $derived(authOnlyPaths.includes($page.url.pathname));
const isHomepage = $derived($page.url.pathname === '/');
const user = $derived(getCurrentUser());

const showHeader = $derived(
	!isAuthPage && (user || !isHomepage)
);
</script>

<BetaBanner />
<Toaster />
{#if showHeader}
<Header />
<VerificationBanner />
{/if}

<div class="container">
	<!-- Background orbs -->
    <div class="fixed inset-0 -z-10">
        <div class="absolute rounded-full mix-blend-multiply filter blur-3xl top-10 left-1/4 w-[600px] h-[600px] bg-[var(--color-divine-green)]/5 animate-blob"></div>
        <div class="absolute rounded-full mix-blend-multiply filter blur-3xl top-1/2 -right-20 w-96 h-96 bg-teal-500/5 animate-blob animation-delay-2000"></div>
        <div class="absolute rounded-full mix-blend-multiply filter blur-3xl bottom-20 left-32 w-72 h-72 bg-cyan-500/5 animate-blob animation-delay-5500"></div>
    </div>
	{@render children()}
</div>


<style>
	@keyframes blob {
        0% { transform: translate(0px, 0px) scale(1); }
        33% { transform: translate(30px, -50px) scale(1.4); }
        66% { transform: translate(-20px, 20px) scale(0.8); }
        100% { transform: translate(0px, 0px) scale(1); }
    }

    .animate-blob {
        animation: blob 14s infinite;
    }

    .animation-delay-2000 {
        animation-delay: 2s;
    }

    .animation-delay-5500 {
        animation-delay: 5.5s;
    }
</style>
