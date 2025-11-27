<script lang="ts">
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import ndk from "$lib/ndk.svelte";
import { SigninMethod, signin } from "$lib/utils/auth";
import { KeycastApi } from "$lib/keycast_api.svelte";
import type { TeamWithRelations, BunkerSession } from "$lib/types";
import { NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { Users, Key, ArrowRight, PlusCircle } from "phosphor-svelte";
import Loader from "$lib/components/Loader.svelte";
import { onMount } from "svelte";
import { nip19 } from "nostr-tools";

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
	<title>{user ? 'Dashboard' : 'Welcome'} - Keycast</title>
</svelte:head>

{#if isCheckingAuth}
	<!-- Show loader while checking authentication -->
	<div class="flex items-center justify-center min-h-screen">
		<Loader />
	</div>
{:else if user}
	<!-- Dashboard for authenticated users -->
	<div class="dashboard">
		<div class="dashboard-header">
			<h1 class="text-3xl font-bold mb-2">Dashboard</h1>
			<p class="text-gray-400">Overview of your teams and connected apps</p>
		</div>

		{#if isLoadingDashboard}
			<Loader />
		{:else}
			<!-- Stats Cards -->
			<div class="stats-grid">
				<!-- User Card -->
				<div class="stat-card">
					<div class="stat-icon">
						<Key size={24} weight="fill" />
					</div>
					<div class="stat-content" style="min-width: 0;">
						<p class="stat-label">Your Account</p>
						{#if userName}
							<p class="stat-value text-base truncate">{userName}</p>
							<p class="stat-meta text-xs truncate" title={userNpub}>{userNpub.slice(0, 10)}...{userNpub.slice(-6)}</p>
						{:else}
							<p class="stat-value text-xs truncate" title={userNpub}>{userNpub.slice(0, 10)}...{userNpub.slice(-6)}</p>
						{/if}
						<p class="stat-meta text-xs text-gray-500 mt-1">
							{authMethod === 'nip07' ? 'NIP-07 Extension' : 'Email/Password'}
						</p>
					</div>
				</div>

				<!-- Teams Card -->
				<!-- svelte-ignore a11y_click_events_have_key_events -->
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<div class="stat-card clickable" onclick={() => window.location.href = '/teams'}>
					<div class="stat-icon">
						<Users size={24} weight="fill" />
					</div>
					<div class="stat-content">
						<p class="stat-label">Teams</p>
						<p class="stat-value">{teams.length}</p>
						<p class="stat-meta">
							{#if teams.length === 0}
								No teams yet
							{:else if teams.length === 1}
								1 team
							{:else}
								{teams.length} teams
							{/if}
						</p>
					</div>
					<ArrowRight size={20} class="stat-arrow" />
				</div>

				<!-- Sessions Card -->
				<!-- svelte-ignore a11y_click_events_have_key_events -->
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<div class="stat-card clickable" onclick={() => window.location.href = '/settings/connected-apps'}>
					<div class="stat-icon">
						<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 256 256">
							<path d="M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z" opacity="0.2"></path>
							<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,192a88,88,0,1,1,88-88A88.1,88.1,0,0,1,128,216Zm40-68a28,28,0,0,1-28,28h-4v8a8,8,0,0,1-16,0v-8H104a8,8,0,0,1,0-16h36a12,12,0,0,0,0-24H116a28,28,0,0,1,0-56h4V72a8,8,0,0,1,16,0v8h16a8,8,0,0,1,0,16H116a12,12,0,0,0,0,24h24A28,28,0,0,1,168,148Z"></path>
						</svg>
					</div>
					<div class="stat-content">
						<p class="stat-label">Connected Apps</p>
						<p class="stat-value">{sessions.length}</p>
						<p class="stat-meta">
							{#if sessions.length === 0}
								No active sessions
							{:else if sessions.length === 1}
								1 app connected
							{:else}
								{sessions.length} apps connected
							{/if}
						</p>
					</div>
					<ArrowRight size={20} class="stat-arrow" />
				</div>

				<!-- Security Settings Card (only for email/password users) -->
				{#if authMethod === 'cookie'}
					<!-- svelte-ignore a11y_click_events_have_key_events -->
					<!-- svelte-ignore a11y_no_static_element_interactions -->
					<div class="stat-card clickable" onclick={() => window.location.href = '/settings/security'}>
						<div class="stat-icon">
							<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 256 256">
								<path d="M208,80H176V56a48,48,0,0,0-96,0V80H48A16,16,0,0,0,32,96V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V96A16,16,0,0,0,208,80ZM96,56a32,32,0,0,1,64,0V80H96ZM208,208H48V96H208V208Zm-68-56a12,12,0,1,1-12-12A12,12,0,0,1,140,152Z"></path>
							</svg>
						</div>
						<div class="stat-content">
							<p class="stat-label">Security</p>
							<p class="stat-value text-sm">Key Management</p>
							<p class="stat-meta">Export or change your private key</p>
						</div>
						<ArrowRight size={20} class="stat-arrow" />
					</div>
				{/if}
			</div>

			<!-- Quick Actions -->
			<div class="quick-actions">
				<h2 class="text-xl font-semibold mb-4">Quick Actions</h2>
				<div class="actions-grid">
					{#if isWhitelisted}
						<a href="/teams" class="action-card">
							<PlusCircle size={20} />
							<span>Create Team</span>
						</a>
					{/if}
					<a href="/settings/connected-apps" class="action-card">
						<Key size={20} />
						<span>Add Bunker Connection</span>
					</a>
					<a href="/teams" class="action-card">
						<Users size={20} />
						<span>View All Teams</span>
					</a>
					{#if authMethod === 'cookie'}
						<a href="/settings/security" class="action-card">
							<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 256 256">
								<path d="M208,80H176V56a48,48,0,0,0-96,0V80H48A16,16,0,0,0,32,96V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V96A16,16,0,0,0,208,80ZM96,56a32,32,0,0,1,64,0V80H96ZM208,208H48V96H208V208Zm-68-56a12,12,0,1,1-12-12A12,12,0,0,1,140,152Z"></path>
							</svg>
							<span>Security Settings</span>
						</a>
					{/if}
				</div>
			</div>

			<!-- Recent Activity -->
			{#if teams.length > 0}
				<div class="section">
					<div class="section-header">
						<h2 class="text-xl font-semibold">Your Teams</h2>
						<a href="/teams" class="text-sm text-indigo-400 hover:text-indigo-300">
							View all →
						</a>
					</div>
					<div class="teams-list">
						{#each teams.slice(0, 3) as team}
							<a href="/teams/{team.team.id}" class="team-item">
								<div class="flex flex-col gap-1">
									<p class="font-medium">{team.team.name}</p>
									<p class="text-sm text-gray-400">
										{team.team_users.length} members • {team.stored_keys.length} keys
									</p>
								</div>
								<ArrowRight size={16} class="text-gray-500" />
							</a>
						{/each}
					</div>
				</div>
			{/if}

			{#if sessions.length > 0}
				<div class="section">
					<div class="section-header">
						<h2 class="text-xl font-semibold">Recent Connections</h2>
						<a href="/settings/connected-apps" class="text-sm text-indigo-400 hover:text-indigo-300">
							View all →
						</a>
					</div>
					<div class="sessions-list">
						{#each sessions.slice(0, 5) as session}
							<div class="session-item">
								<div class="flex flex-col gap-1">
									<p class="font-medium">{session.application_name}</p>
									<p class="text-sm text-gray-400">
										{session.activity_count} activities
										{#if session.last_activity}
											• Last: {new Date(session.last_activity).toLocaleDateString()}
										{/if}
									</p>
								</div>
							</div>
						{/each}
					</div>
				</div>
			{/if}
		{/if}
	</div>
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
				<span>Keycast</span>
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
		max-width: 1200px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}

	.dashboard-header {
		margin-bottom: 2rem;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
		gap: 1.5rem;
		margin-bottom: 3rem;
	}

	.stat-card {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		padding: 1.5rem;
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		position: relative;
		transition: all 0.2s;
	}

	.stat-card.clickable {
		cursor: pointer;
	}

	.stat-card.clickable:hover {
		border-color: rgb(99 102 241);
		background: #222;
	}

	.stat-icon {
		background: rgb(79 70 229 / 0.15);
		border-radius: 8px;
		padding: 0.75rem;
		color: rgb(129 140 248);
		flex-shrink: 0;
	}

	.stat-content {
		flex: 1;
	}

	.stat-label {
		color: #999;
		font-size: 0.875rem;
		margin-bottom: 0.25rem;
	}

	.stat-value {
		font-size: 1.5rem;
		font-weight: 700;
		color: #e0e0e0;
		margin-bottom: 0.25rem;
	}

	.stat-meta {
		color: #666;
		font-size: 0.875rem;
	}

	.stat-card :global(.stat-arrow) {
		position: absolute;
		top: 1.5rem;
		right: 1.5rem;
		color: #666;
		transition: all 0.2s;
	}

	.stat-card.clickable:hover :global(.stat-arrow) {
		color: rgb(129 140 248);
		transform: translateX(4px);
	}

	.quick-actions {
		margin-bottom: 3rem;
	}

	.actions-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
	}

	.action-card {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 8px;
		padding: 1rem 1.5rem;
		display: flex;
		align-items: center;
		gap: 0.75rem;
		color: #e0e0e0;
		text-decoration: none;
		transition: all 0.2s;
	}

	.action-card:hover {
		border-color: rgb(99 102 241);
		background: #222;
		color: #fff;
	}

	.section {
		margin-bottom: 2rem;
	}

	.section-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.teams-list, .sessions-list {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		overflow: hidden;
	}

	.team-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.5rem;
		border-bottom: 1px solid #333;
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

	.session-item {
		padding: 1rem 1.5rem;
		border-bottom: 1px solid #333;
	}

	.session-item:last-child {
		border-bottom: none;
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
