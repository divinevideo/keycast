<script lang="ts">
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import ndk from "$lib/ndk.svelte";
import { SigninMethod, signin } from "$lib/utils/auth";
import { KeycastApi } from "$lib/keycast_api.svelte";
import { BRAND } from "$lib/brand";
import type { TeamWithRelations, BunkerSession } from "$lib/types";
import { NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { Users, Key, ArrowRight, PlusCircle, Gear, Copy, Check, EnvelopeSimple } from "phosphor-svelte";
import Loader from "$lib/components/Loader.svelte";
import CreateBunkerModal from "$lib/components/CreateBunkerModal.svelte";
import { onMount } from "svelte";
import { nip19 } from "nostr-tools";
import { toast } from "svelte-hot-french-toast";

const api = new KeycastApi();
const currentUser = $derived(getCurrentUser());
const user = $derived(currentUser?.user);
const authMethod = $derived(currentUser?.authMethod);

let teams = $state<TeamWithRelations[]>([]);
let sessions = $state<BunkerSession[]>([]);
let isLoadingDashboard = $state(true);
let isCheckingAuth = $state(true);
let error = $state('');
let userNpub = $state('');
let userName = $state('');
let userEmail = $state('');
let emailVerified = $state(false);
let showCreateModal = $state(false);
let copiedNpub = $state(false);

// Check if user is whitelisted for team creation
const isWhitelisted = $derived(
	user?.pubkey ? JSON.stringify(import.meta.env.VITE_ALLOWED_PUBKEYS).includes(user.pubkey) : false
);

function handleNip07Signin() {
	signin(ndk, undefined, SigninMethod.Nip07);
}

async function loadTeams() {
	if (!user?.pubkey) return;

	try {
		let authHeaders: Record<string, string> = {};

		if (authMethod === 'nip07') {
			if (!ndk.signer) {
				ndk.signer = new NDKNip07Signer();
			}
			const authEvent = await api.buildUnsignedAuthEvent('/teams', 'GET', user.pubkey);
			await authEvent?.sign();
			authHeaders.Authorization = `Nostr ${btoa(JSON.stringify(authEvent))}`;
		}

		const response = await api.get<TeamWithRelations[]>('/teams', {
			headers: authHeaders
		});
		teams = response || [];
	} catch (err: any) {
		console.error('Failed to load teams:', err);
		teams = [];
	}
}

async function loadSessions() {
	if (!user?.pubkey) return;

	try {
		let authHeaders: Record<string, string> = {};

		if (authMethod === 'nip07') {
			if (!ndk.signer) {
				ndk.signer = new NDKNip07Signer();
			}
			const authEvent = await api.buildUnsignedAuthEvent('/user/sessions', 'GET', user.pubkey);
			await authEvent?.sign();
			authHeaders.Authorization = `Nostr ${btoa(JSON.stringify(authEvent))}`;
		}

		const response = await api.get<{ sessions: BunkerSession[] }>('/user/sessions', {
			headers: authHeaders
		});
		sessions = response.sessions || [];
	} catch (err: any) {
		console.error('Failed to load sessions:', err);
		sessions = [];
	}
}

async function copyNpub() {
	try {
		await navigator.clipboard.writeText(userNpub);
		copiedNpub = true;
		toast.success('Copied to clipboard');
		setTimeout(() => (copiedNpub = false), 2000);
	} catch (err) {
		toast.error('Failed to copy');
	}
}

async function revokeSession(secret: string, appName: string) {
	try {
		let authHeaders: Record<string, string> = {};

		if (authMethod === 'nip07' && ndk.signer) {
			const body = JSON.stringify({ secret });
			const authEvent = await api.buildUnsignedAuthEvent('/user/sessions/revoke', 'POST', user!.pubkey, body);
			await authEvent?.sign();
			authHeaders.Authorization = `Nostr ${btoa(JSON.stringify(authEvent))}`;
		}

		await api.post('/user/sessions/revoke', { secret }, { headers: authHeaders });
		toast.success(`Revoked access for ${appName}`);
		await loadSessions();
	} catch (err) {
		toast.error('Failed to revoke session');
	}
}

onMount(async () => {
	// Check for cookie-based authentication first
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
					// Store email info if available
					if (data.email) {
						userEmail = data.email;
						emailVerified = data.email_verified || false;
					}
				}
			}
		} catch (err) {
			console.warn('Failed to check auth status:', err);
		}
	}

	// Auth check complete
	isCheckingAuth = false;

	// Wait a tick for user to be set
	await new Promise(resolve => setTimeout(resolve, 50));

	const currentUserCheck = getCurrentUser();
	if (currentUserCheck?.user?.pubkey) {
		const userObj = currentUserCheck.user;

		// Convert hex pubkey to npub
		try {
			userNpub = nip19.npubEncode(userObj.pubkey);
		} catch (e) {
			userNpub = userObj.pubkey;
		}

		// Load dashboard data
		await Promise.all([loadTeams(), loadSessions()]);
		isLoadingDashboard = false;

		// Try to fetch user profile for name
		try {
			const profile = await userObj.fetchProfile();
			if (profile?.name || profile?.displayName) {
				userName = profile.displayName || profile.name || '';
			}
		} catch (e) {
			console.log('Could not fetch profile:', e);
		}
	}
});
</script>

<svelte:head>
	<title>{user ? 'Dashboard' : 'Welcome'} - {BRAND.name}</title>
</svelte:head>

{#if isCheckingAuth}
	<!-- Show loader while checking authentication -->
	<div class="flex items-center justify-center min-h-screen">
		<Loader />
	</div>
{:else if user}
	<!-- Dashboard for authenticated users -->
	<div class="dashboard">
		{#if isLoadingDashboard}
			<Loader />
		{:else}
			<!-- Your Identity Section -->
			<section class="identity-section">
				<h2 class="section-title">Your Identity</h2>
				<div class="identity-card">
					{#if userEmail}
						<div class="identity-row">
							<div class="identity-icon">
								<EnvelopeSimple size={20} weight="fill" />
							</div>
							<div class="identity-info">
								<span class="identity-value">{userEmail}</span>
								{#if !emailVerified}
									<span class="status-badge warning">Not verified</span>
								{:else}
									<span class="status-badge success">Verified</span>
								{/if}
							</div>
						</div>
					{/if}
					<div class="identity-row">
						<div class="identity-icon">
							<Key size={20} weight="fill" />
						</div>
						<div class="identity-info">
							<span class="identity-value mono" title={userNpub}>
								{userNpub.slice(0, 12)}...{userNpub.slice(-8)}
							</span>
							<button class="copy-btn" onclick={copyNpub} title="Copy full npub">
								{#if copiedNpub}
									<Check size={16} />
								{:else}
									<Copy size={16} />
								{/if}
							</button>
						</div>
					</div>
					{#if authMethod === 'cookie'}
						<div class="identity-actions">
							<a href="/settings/security" class="identity-link">
								<Gear size={16} />
								<span>Security Settings</span>
							</a>
						</div>
					{/if}
				</div>
			</section>

			<!-- Connected Apps Section -->
			<section class="apps-section">
				<div class="section-header">
					<h2 class="section-title">Connected Apps</h2>
					<button class="btn-connect" onclick={() => (showCreateModal = true)}>
						<PlusCircle size={18} />
						<span>Connect to Nostr App</span>
					</button>
				</div>

				{#if sessions.length === 0}
					<div class="empty-state">
						<p>No apps connected yet.</p>
						<p class="hint">Connect your diVine ID to Nostr apps that support NIP-46 remote signing.</p>
					</div>
				{:else}
					<div class="apps-list">
						{#each sessions as session}
							<div class="app-item">
								<div class="app-info">
									<p class="app-name">{session.application_name}</p>
									<p class="app-meta">
										{session.activity_count} signatures
										{#if session.last_activity}
											• Last used {new Date(session.last_activity).toLocaleDateString()}
										{/if}
									</p>
								</div>
								<button
									class="btn-revoke"
									onclick={() => revokeSession(session.secret, session.application_name)}
								>
									Revoke
								</button>
							</div>
						{/each}
					</div>
				{/if}
			</section>

			<!-- Teams Section (only if user has teams or is whitelisted) -->
			{#if teams.length > 0 || isWhitelisted}
				<section class="teams-section">
					<div class="section-header">
						<h2 class="section-title">Teams</h2>
						{#if isWhitelisted}
							<a href="/teams" class="btn-link">
								<PlusCircle size={18} />
								<span>Create Team</span>
							</a>
						{/if}
					</div>

					{#if teams.length === 0}
						<div class="empty-state">
							<p>No teams yet.</p>
							<p class="hint">Teams let you manage shared Nostr keys with role-based permissions.</p>
						</div>
					{:else}
						<div class="teams-list">
							{#each teams as team}
								<a href="/teams/{team.team.id}" class="team-item">
									<div class="team-info">
										<p class="team-name">{team.team.name}</p>
										<p class="team-meta">
											{team.team_users.length} members • {team.stored_keys.length} keys
										</p>
									</div>
									<ArrowRight size={16} class="arrow-icon" />
								</a>
							{/each}
						</div>
					{/if}
				</section>
			{/if}
		{/if}
	</div>

	<CreateBunkerModal
		bind:show={showCreateModal}
		onClose={() => (showCreateModal = false)}
		onSuccess={() => {
			showCreateModal = false;
			loadSessions();
		}}
	/>
{:else}
	<!-- Marketing page for unauthenticated users -->
	<div class="relative min-h-screen overflow-hidden">
		<!-- Content -->
		<div class="flex flex-col items-center justify-center mt-8 md:mt-20 relative">
			<!-- Logo/Branding -->
			<a href="/" class="flex flex-row items-center gap-3 mb-8 text-2xl font-bold text-white hover:text-gray-300 transition-colors">
				<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" viewBox="0 0 256 256">
					<path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
				</svg>
				<span>{BRAND.name}</span>
			</a>

			<h1 class="text-4xl md:text-5xl font-extrabold">Work Together</h1>
			<h1 class="text-2xl md:text-4xl font-light text-gray-400">without losing your keys</h1>

			<!-- CTAs -->
			<div class="flex flex-col items-center gap-4 mt-8">
				<div class="flex flex-row gap-4">
					<a href="/register" class="button button-primary">Get Started</a>
					<a href="/login" class="button button-secondary">Sign In</a>
				</div>
				<p class="text-gray-500 text-sm">or</p>
				<button onclick={handleNip07Signin} class="button button-secondary">Sign In with NIP-07 Extension</button>
			</div>

			<!-- Feature sections -->
			<div class="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto mt-20 px-6">
				<!-- Team Management -->
				<div class="feature-panel">
					<h3 class="text-xl font-bold mb-3">Manage Multiple Teams</h3>
					<p class="text-gray-400">
						Easily manage keys across multiple teams with secure, organized access control.
					</p>
				</div>

				<!-- Custom Policies -->
				<div class="feature-panel">
					<h3 class="text-xl font-bold mb-3">Custom Permissions</h3>
					<p class="text-gray-400">
						Create granular policies to control who can sign, encrypt, or decrypt specific events.
					</p>
				</div>

				<!-- NIP-46 Security -->
				<div class="feature-panel">
					<h3 class="text-xl font-bold mb-3">Secure Remote Signing</h3>
					<p class="text-gray-400">
						Use NIP-46 remote signing to keep private keys encrypted and secure across all clients.
					</p>
				</div>
			</div>
		</div>
	</div>
{/if}

<style>
	/* Dashboard Styles */
	.dashboard {
		max-width: 800px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}

	/* Section Styles */
	section {
		margin-bottom: 2.5rem;
	}

	.section-title {
		font-size: 1.25rem;
		font-weight: 600;
		color: #e0e0e0;
		margin-bottom: 1rem;
	}

	.section-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	/* Identity Section */
	.identity-card {
		background: var(--color-divine-surface);
		border: 1px solid #333;
		border-radius: 12px;
		padding: 1.25rem;
	}

	.identity-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 0;
		border-bottom: 1px solid #2a2a2a;
	}

	.identity-row:last-child {
		border-bottom: none;
	}

	.identity-icon {
		color: var(--color-divine-green);
		flex-shrink: 0;
	}

	.identity-info {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		flex: 1;
		min-width: 0;
	}

	.identity-value {
		color: #e0e0e0;
		font-size: 0.95rem;
	}

	.identity-value.mono {
		font-family: monospace;
		font-size: 0.875rem;
	}

	.status-badge {
		font-size: 0.75rem;
		padding: 0.125rem 0.5rem;
		border-radius: 9999px;
		font-weight: 500;
	}

	.status-badge.warning {
		background: color-mix(in srgb, var(--color-divine-warning) 20%, transparent);
		color: var(--color-divine-warning);
	}

	.status-badge.success {
		background: color-mix(in srgb, var(--color-divine-green) 20%, transparent);
		color: var(--color-divine-green);
	}

	.copy-btn {
		background: transparent;
		border: none;
		color: #666;
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 4px;
		transition: all 0.2s;
	}

	.copy-btn:hover {
		color: var(--color-divine-green);
		background: #2a2a2a;
	}

	.identity-actions {
		padding-top: 0.75rem;
		margin-top: 0.5rem;
		border-top: 1px solid #2a2a2a;
	}

	.identity-link {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--color-divine-purple-light);
		text-decoration: none;
		font-size: 0.875rem;
		transition: color 0.2s;
	}

	.identity-link:hover {
		color: var(--color-divine-purple);
	}

	/* Connected Apps Section */
	.btn-connect {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 6px;
		font-size: 0.875rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.2s;
	}

	.btn-connect:hover {
		background: var(--color-divine-green-dark);
	}

	.btn-link {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--color-divine-green);
		text-decoration: none;
		font-size: 0.875rem;
		font-weight: 500;
		transition: color 0.2s;
	}

	.btn-link:hover {
		color: var(--color-divine-green-light);
	}

	.empty-state {
		background: var(--color-divine-surface);
		border: 1px dashed #333;
		border-radius: 12px;
		padding: 2rem;
		text-align: center;
		color: #888;
	}

	.empty-state .hint {
		font-size: 0.875rem;
		color: #666;
		margin-top: 0.5rem;
	}

	.apps-list {
		background: var(--color-divine-surface);
		border: 1px solid #333;
		border-radius: 12px;
		overflow: hidden;
	}

	.app-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid #2a2a2a;
	}

	.app-item:last-child {
		border-bottom: none;
	}

	.app-info {
		min-width: 0;
	}

	.app-name {
		color: #e0e0e0;
		font-weight: 500;
		margin: 0;
	}

	.app-meta {
		color: #666;
		font-size: 0.875rem;
		margin: 0.25rem 0 0 0;
	}

	.btn-revoke {
		padding: 0.375rem 0.75rem;
		background: transparent;
		color: var(--color-divine-error);
		border: 1px solid var(--color-divine-error);
		border-radius: 4px;
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-revoke:hover {
		background: var(--color-divine-error);
		color: #fff;
	}

	/* Teams Section */
	.teams-list {
		background: var(--color-divine-surface);
		border: 1px solid #333;
		border-radius: 12px;
		overflow: hidden;
	}

	.team-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid #2a2a2a;
		color: #e0e0e0;
		text-decoration: none;
		transition: background 0.2s;
	}

	.team-item:last-child {
		border-bottom: none;
	}

	.team-item:hover {
		background: #222;
	}

	.team-info {
		min-width: 0;
	}

	.team-name {
		font-weight: 500;
		margin: 0;
	}

	.team-meta {
		color: #666;
		font-size: 0.875rem;
		margin: 0.25rem 0 0 0;
	}

	.arrow-icon {
		color: #666;
		transition: all 0.2s;
	}

	.team-item:hover .arrow-icon {
		color: var(--color-divine-green);
		transform: translateX(4px);
	}

	/* Marketing Page Styles */
	.feature-panel {
		position: relative;
		overflow: hidden;
	}

	.feature-panel::before {
		content: '';
		position: absolute;
		top: 0;
		left: -100%;
		width: 200%;
		height: 100%;
		background: linear-gradient(
			115deg,
			transparent 0%,
			transparent 40%,
			rgba(255, 255, 255, 0.04) 45%,
			rgba(255, 255, 255, 0.10) 50%,
			rgba(255, 255, 255, 0.08) 60%,
			rgba(255, 255, 255, 0.04) 75%,
			rgba(255, 255, 255, 0.02) 80%,
			transparent 85%,
			transparent 100%
		);
		pointer-events: none;
	}
</style>
