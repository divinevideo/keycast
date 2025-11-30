<script lang="ts">
import { browser } from "$app/environment";
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import ndk from "$lib/ndk.svelte";
import { SigninMethod, signin } from "$lib/utils/auth";
import { KeycastApi } from "$lib/keycast_api.svelte";
import { BRAND } from "$lib/brand";
import type { TeamWithRelations, BunkerSession } from "$lib/types";
import { NDKNip07Signer } from "@nostr-dev-kit/ndk";
import { Users, Key, ArrowRight, PlusCircle, Gear, Copy, Check, EnvelopeSimple, CaretDown, CaretUp, Question, ArrowSquareOut, ShieldCheck, Export } from "phosphor-svelte";
import Loader from "$lib/components/Loader.svelte";
import CreateBunkerModal from "$lib/components/CreateBunkerModal.svelte";
import { onMount } from "svelte";
import { nip19 } from "nostr-tools";
import { toast } from "svelte-hot-french-toast";

// Detect iOS - no browser extension support for NIP-07
const isIOS = $derived(browser ? /iPad|iPhone|iPod/.test(navigator.userAgent) : false);

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
let expandedSessions = $state<Set<string>>(new Set());
let showRevokeModal = $state(false);
let sessionToRevoke = $state<BunkerSession | null>(null);
let copiedBunkerUrl = $state<string | null>(null);
let showLearnMore = $state(false);
let pubkeyFormat = $state<'hex' | 'npub'>('npub');
let copiedPubkey = $state<string | null>(null);

function formatPubkey(hexPubkey: string): string {
	if (pubkeyFormat === 'npub') {
		try {
			return nip19.npubEncode(hexPubkey);
		} catch {
			return hexPubkey;
		}
	}
	return hexPubkey;
}

async function copyPubkey(hexPubkey: string) {
	try {
		const formatted = formatPubkey(hexPubkey);
		await navigator.clipboard.writeText(formatted);
		copiedPubkey = hexPubkey;
		toast.success(`${pubkeyFormat === 'npub' ? 'npub' : 'Hex pubkey'} copied!`);
		setTimeout(() => (copiedPubkey = null), 2000);
	} catch (err) {
		toast.error('Failed to copy');
	}
}

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

async function copyBunkerUrl(bunkerUrl: string) {
	try {
		await navigator.clipboard.writeText(bunkerUrl);
		copiedBunkerUrl = bunkerUrl;
		toast.success('Bunker URL copied!');
		setTimeout(() => (copiedBunkerUrl = null), 2000);
	} catch (err) {
		toast.error('Failed to copy');
	}
}

function toggleSession(secret: string) {
	const newSet = new Set(expandedSessions);
	if (newSet.has(secret)) {
		newSet.delete(secret);
	} else {
		newSet.add(secret);
	}
	expandedSessions = newSet;
}

function formatDate(dateStr: string): string {
	const date = new Date(dateStr);
	return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function confirmRevoke(session: BunkerSession) {
	sessionToRevoke = session;
	showRevokeModal = true;
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
		showRevokeModal = false;
		sessionToRevoke = null;
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
	} else if (authMethod === 'cookie') {
		// User is already logged in via cookie, but we still need to fetch email info
		try {
			const response = await fetch('/api/oauth/auth-status', {
				credentials: 'include'
			});
			if (response.ok) {
				const data = await response.json();
				if (data.email) {
					userEmail = data.email;
					emailVerified = data.email_verified || false;
				}
			}
		} catch (err) {
			console.warn('Failed to fetch email info:', err);
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
				<h2 class="section-title">Manage Your Identity</h2>
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
							<a href="https://nostr.how/en/get-started" target="_blank" rel="noopener noreferrer" class="learn-link" title="What's an npub?">
								?
							</a>
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

			<!-- Learn More Section -->
			<section class="learn-section">
				<button class="learn-toggle" onclick={() => (showLearnMore = !showLearnMore)}>
					<Question size={18} weight="fill" />
					<span>Understanding Your Nostr Identity</span>
					{#if showLearnMore}
						<CaretUp size={16} />
					{:else}
						<CaretDown size={16} />
					{/if}
				</button>

				{#if showLearnMore}
					<div class="learn-content">
						<div class="learn-block">
							<h4><Key size={16} weight="fill" /> Your Keys Explained</h4>
							<p><strong>Your npub</strong> (public key) is like a username — share it so others can find you across any Nostr app.</p>
							<p><strong>Your nsec</strong> (private key) proves you own this identity. Keep it safe! Find it in <a href="/settings/security">Security Settings</a> if you need to export it.</p>
						</div>

						<div class="learn-block">
							<h4><ShieldCheck size={16} weight="fill" /> Where Is Your Key?</h4>
							<p>diVine stores your encrypted key and signs on your behalf — similar to trusting Google or Apple with your data. This makes getting started easy.</p>
							<p class="learn-subtle">Want more control? You can:</p>
							<ul class="learn-list">
								<li><a href="https://getalby.com" target="_blank" rel="noopener noreferrer">Alby <ArrowSquareOut size={12} /></a> or <a href="https://github.com/fiatjaf/nos2x" target="_blank" rel="noopener noreferrer">nos2x <ArrowSquareOut size={12} /></a> — browser extensions where your key never leaves your device</li>
								<li><a href="https://nsec.app" target="_blank" rel="noopener noreferrer">nsec.app <ArrowSquareOut size={12} /></a> — non-custodial signer, encrypted with your password</li>
								<li><a href="https://nsecbunker.com" target="_blank" rel="noopener noreferrer">nsecBunker <ArrowSquareOut size={12} /></a> — self-host for full control</li>
							</ul>
						</div>

						<div class="learn-block highlight">
							<h4><Export size={16} weight="fill" /> Why This Matters</h4>
							<p>Unlike Twitter or Facebook, <strong>no company owns your Nostr identity</strong>. Even if diVine disappeared tomorrow, your identity and content would still exist on the network. Export your key and continue anywhere.</p>
							<p class="learn-cta">That's the power of Nostr.</p>
						</div>
					</div>
				{/if}
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
						<p class="hint">
							Connect your diVine Login to Nostr apps to sign in without sharing your private key.
							<a href="https://nostr.how/en/get-started" target="_blank" rel="noopener noreferrer">Learn more</a>
						</p>
					</div>
				{:else}
					<div class="apps-list">
						{#each sessions as session}
							{@const isExpanded = expandedSessions.has(session.secret)}
							<div class="app-card" class:expanded={isExpanded}>
								<button class="app-header" onclick={() => toggleSession(session.secret)}>
									<div class="app-info">
										<p class="app-name">{session.application_name}</p>
										<p class="app-meta">
											{#if session.activity_count > 0}
												{session.activity_count} {session.activity_count === 1 ? 'request' : 'requests'}
												{#if session.last_activity}
													• Last used {new Date(session.last_activity).toLocaleDateString()}
												{/if}
											{:else}
												Not used yet
											{/if}
										</p>
									</div>
									<div class="app-expand-icon">
										{#if isExpanded}
											<CaretUp size={18} />
										{:else}
											<CaretDown size={18} />
										{/if}
									</div>
								</button>

								{#if isExpanded}
									<div class="app-details">
										<div class="details-grid">
											<div class="detail-item full-width">
												<span class="detail-label">Domain</span>
												<span class="detail-value">{session.redirect_origin}</span>
											</div>
											<div class="detail-item">
												<span class="detail-label">Created</span>
												<span class="detail-value">{formatDate(session.created_at)}</span>
											</div>
											<div class="detail-item">
												<span class="detail-label">Last Activity</span>
												<span class="detail-value">
													{session.last_activity ? formatDate(session.last_activity) : 'Never'}
												</span>
											</div>
											<div class="detail-item">
												<span class="detail-label">Total Requests</span>
												<span class="detail-value">{session.activity_count}</span>
											</div>
											{#if session.client_pubkey}
												<div class="detail-item full-width pubkey-row">
													<div class="detail-header">
														<span class="detail-label">Client Pubkey</span>
														<button
															class="format-toggle"
															onclick={(e) => { e.stopPropagation(); pubkeyFormat = pubkeyFormat === 'hex' ? 'npub' : 'hex'; }}
														>
															{pubkeyFormat === 'hex' ? 'npub' : 'hex'}
														</button>
													</div>
													<div class="pubkey-value">
														<span class="detail-value mono">{formatPubkey(session.client_pubkey)}</span>
														<button
															class="copy-btn-inline"
															onclick={(e) => { e.stopPropagation(); copyPubkey(session.client_pubkey); }}
														>
															{#if copiedPubkey === session.client_pubkey}
																<Check size={14} />
															{:else}
																<Copy size={14} />
															{/if}
														</button>
													</div>
												</div>
											{/if}
											<div class="detail-item full-width pubkey-row">
												<div class="detail-header">
													<span class="detail-label">Bunker Pubkey</span>
													{#if !session.client_pubkey}
														<button
															class="format-toggle"
															onclick={(e) => { e.stopPropagation(); pubkeyFormat = pubkeyFormat === 'hex' ? 'npub' : 'hex'; }}
														>
															{pubkeyFormat === 'hex' ? 'npub' : 'hex'}
														</button>
													{/if}
												</div>
												<div class="pubkey-value">
													<span class="detail-value mono">{formatPubkey(session.bunker_pubkey)}</span>
													<button
														class="copy-btn-inline"
														onclick={(e) => { e.stopPropagation(); copyPubkey(session.bunker_pubkey); }}
													>
														{#if copiedPubkey === session.bunker_pubkey}
															<Check size={14} />
														{:else}
															<Copy size={14} />
														{/if}
													</button>
												</div>
											</div>
										</div>
										<div class="app-actions">
											<button
												class="btn-copy-bunker"
												onclick={(e) => { e.stopPropagation(); copyBunkerUrl(session.bunker_url); }}
											>
												{#if copiedBunkerUrl === session.bunker_url}
													<Check size={16} />
													Copied!
												{:else}
													<Copy size={16} />
													Copy Bunker URL
												{/if}
											</button>
											<button
												class="btn-revoke"
												onclick={(e) => { e.stopPropagation(); confirmRevoke(session); }}
											>
												Revoke Access
											</button>
										</div>
									</div>
								{/if}
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

	{#if showRevokeModal && sessionToRevoke}
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="modal-overlay" onclick={() => { showRevokeModal = false; sessionToRevoke = null; }}>
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="modal" onclick={(e) => e.stopPropagation()}>
				<h3>Revoke Access?</h3>
				<p>
					Are you sure you want to revoke access for
					<strong>{sessionToRevoke.application_name}</strong>?
				</p>
				<p class="modal-warning">This app will no longer be able to sign events on your behalf.</p>
				<div class="modal-actions">
					<button class="btn-cancel" onclick={() => { showRevokeModal = false; sessionToRevoke = null; }}>
						Cancel
					</button>
					<button
						class="btn-confirm-revoke"
						onclick={() => sessionToRevoke && revokeSession(sessionToRevoke.secret, sessionToRevoke.application_name)}
					>
						Revoke Access
					</button>
				</div>
			</div>
		</div>
	{/if}
{:else}
	<!-- Marketing page for unauthenticated users -->
	<div class="landing-page">
		<!-- Content -->
		<div class="landing-content">
			<!-- Logo/Branding -->
			<a href="/" class="landing-logo">
				<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
					<path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
				</svg>
				<span>{BRAND.name}</span>
			</a>

			<h1 class="landing-title">Manage Your Nostr Identity</h1>
			<p class="landing-subtitle">Secure your keys. Connect everywhere.</p>

			<!-- CTAs -->
			<div class="landing-ctas">
				<a href="/register" class="button button-primary">Get Started</a>
				<a href="/login" class="button button-secondary">Sign In</a>
			</div>

			<!-- NIP-07 option - hidden on iOS -->
			{#if !isIOS}
				<div class="landing-divider">
					<span>or sign in with</span>
				</div>
				<button onclick={handleNip07Signin} class="nip07-button">
					<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 256 256">
						<path d="M160,16A80.07,80.07,0,0,0,83.91,120.78L26.34,178.34A8,8,0,0,0,24,184v40a8,8,0,0,0,8,8H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A80,80,0,1,0,160,16Zm20,76a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
					</svg>
					Browser Extension (NIP-07)
				</button>
			{/if}

			<!-- Feature sections -->
			<div class="features-grid">
				<div class="feature-card">
					<div class="feature-icon">
						<Key size={24} weight="fill" />
					</div>
					<h3>One Identity, Every App</h3>
					<p>Use one account across all Nostr apps. No more creating accounts everywhere.</p>
				</div>

				<div class="feature-card">
					<div class="feature-icon">
						<Users size={24} weight="fill" />
					</div>
					<h3>You Own Your Account</h3>
					<p>Your identity belongs to you, not any company. Take it anywhere, keep it forever.</p>
				</div>

				<div class="feature-card">
					<div class="feature-icon">
						<Gear size={24} weight="fill" />
					</div>
					<h3>Easy to Start</h3>
					<p>No extensions needed. Get started quickly, then export your key anytime to take full control.</p>
				</div>
			</div>

			<p class="nostr-learn-more">
				New to Nostr? <a href="https://nostr.how/en/what-is-nostr" target="_blank" rel="noopener noreferrer">Learn how it works</a>
			</p>
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
		color: var(--color-divine-text);
		margin-bottom: 1rem;
	}

	.section-header {
		display: flex;
		flex-wrap: wrap;
		justify-content: space-between;
		align-items: center;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	@media (max-width: 480px) {
		.section-header {
			flex-direction: column;
			align-items: stretch;
		}

		.section-header .section-title {
			margin-bottom: 0;
		}

		.btn-connect,
		.btn-link {
			justify-content: center;
		}
	}

	/* Identity Section */
	.identity-card {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 1.25rem;
	}

	.identity-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 0;
		border-bottom: 1px solid var(--color-divine-border);
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
		color: var(--color-divine-text);
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
		color: var(--color-divine-text-tertiary);
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 4px;
		transition: all 0.2s;
	}

	.copy-btn:hover {
		color: var(--color-divine-green);
		background: var(--color-divine-muted);
	}

	.learn-link {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 18px;
		height: 18px;
		font-size: 0.7rem;
		font-weight: 600;
		color: var(--color-divine-text-tertiary);
		background: var(--color-divine-muted);
		border-radius: 50%;
		text-decoration: none;
		transition: all 0.2s;
	}

	.learn-link:hover {
		color: var(--color-divine-green);
		background: color-mix(in srgb, var(--color-divine-green) 20%, transparent);
	}

	.identity-actions {
		padding-top: 0.75rem;
		margin-top: 0.5rem;
		border-top: 1px solid var(--color-divine-border);
	}

	.identity-link {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--color-divine-green);
		text-decoration: none;
		font-size: 0.875rem;
		transition: color 0.2s;
	}

	.identity-link:hover {
		color: var(--color-divine-green-dark);
	}

	/* Learn More Section */
	.learn-section {
		margin-bottom: 2rem;
	}

	.learn-toggle {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.875rem 1rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 10px;
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
	}

	.learn-toggle:hover {
		background: var(--color-divine-muted);
		color: var(--color-divine-text);
	}

	.learn-toggle span {
		flex: 1;
		text-align: left;
	}

	.learn-content {
		margin-top: 0.75rem;
		padding: 1.25rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 10px;
	}

	.learn-block {
		padding-bottom: 1rem;
		margin-bottom: 1rem;
		border-bottom: 1px solid var(--color-divine-border);
	}

	.learn-block:last-child {
		padding-bottom: 0;
		margin-bottom: 0;
		border-bottom: none;
	}

	.learn-block h4 {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin: 0 0 0.75rem 0;
		color: var(--color-divine-text);
		font-size: 0.95rem;
		font-weight: 600;
	}

	.learn-block p {
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-text-secondary);
		font-size: 0.875rem;
		line-height: 1.6;
	}

	.learn-block p:last-child {
		margin-bottom: 0;
	}

	.learn-block a {
		color: var(--color-divine-green);
		text-decoration: none;
	}

	.learn-block a:hover {
		text-decoration: underline;
	}

	.learn-subtle {
		color: var(--color-divine-text-tertiary) !important;
		font-size: 0.8rem !important;
		margin-top: 0.75rem !important;
	}

	.learn-list {
		margin: 0.5rem 0 0 0;
		padding-left: 1.25rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.85rem;
		line-height: 1.8;
	}

	.learn-list li {
		margin-bottom: 0.25rem;
	}

	.learn-list a {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
	}

	.learn-block.highlight {
		background: color-mix(in srgb, var(--color-divine-green) 8%, transparent);
		border-radius: 8px;
		padding: 1rem;
		border-bottom: none;
		margin-bottom: 0;
	}

	.learn-cta {
		color: var(--color-divine-green) !important;
		font-weight: 500;
		margin-top: 0.5rem !important;
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
		border-radius: 9999px;
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
		color: var(--color-divine-green-dark);
	}

	.empty-state {
		background: var(--color-divine-surface);
		border: 1px dashed var(--color-divine-border);
		border-radius: 12px;
		padding: 2rem;
		text-align: center;
		color: var(--color-divine-text-secondary);
	}

	.empty-state .hint {
		font-size: 0.875rem;
		color: var(--color-divine-text-tertiary);
		margin-top: 0.5rem;
	}

	.empty-state .hint a {
		color: var(--color-divine-green);
		text-decoration: none;
	}

	.empty-state .hint a:hover {
		text-decoration: underline;
	}

	.apps-list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.app-card {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		overflow: hidden;
		transition: border-color 0.2s;
	}

	.app-card:hover {
		border-color: color-mix(in srgb, var(--color-divine-green) 50%, var(--color-divine-border));
	}

	.app-card.expanded {
		border-color: var(--color-divine-green);
	}

	.app-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 1rem 1.25rem;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
	}

	.app-info {
		min-width: 0;
		flex: 1;
	}

	.app-name {
		color: var(--color-divine-text);
		font-weight: 500;
		margin: 0;
	}

	.app-meta {
		color: var(--color-divine-text-tertiary);
		font-size: 0.875rem;
		margin: 0.25rem 0 0 0;
	}

	.app-expand-icon {
		color: var(--color-divine-text-tertiary);
		flex-shrink: 0;
		transition: color 0.2s;
	}

	.app-card:hover .app-expand-icon {
		color: var(--color-divine-green);
	}

	.app-details {
		padding: 0 1.25rem 1.25rem;
		border-top: 1px solid var(--color-divine-border);
		margin-top: -1px;
	}

	.details-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
		gap: 1rem;
		padding-top: 1rem;
	}

	.detail-item {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.detail-item.full-width {
		grid-column: 1 / -1;
	}

	.detail-label {
		font-size: 0.7rem;
		color: var(--color-divine-text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.detail-value {
		font-size: 0.875rem;
		color: var(--color-divine-text);
	}

	.detail-value.mono {
		font-family: monospace;
		font-size: 0.8rem;
		word-break: break-all;
	}

	.pubkey-row {
		gap: 0.5rem;
	}

	.detail-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.format-toggle {
		font-size: 0.65rem;
		padding: 0.125rem 0.375rem;
		background: var(--color-divine-muted);
		border: 1px solid var(--color-divine-border);
		border-radius: 4px;
		color: var(--color-divine-text-tertiary);
		cursor: pointer;
		transition: all 0.2s;
		text-transform: lowercase;
	}

	.format-toggle:hover {
		color: var(--color-divine-green);
		border-color: var(--color-divine-green);
	}

	.pubkey-value {
		display: flex;
		align-items: flex-start;
		gap: 0.5rem;
	}

	.pubkey-value .detail-value {
		flex: 1;
		font-size: 0.75rem;
		line-height: 1.4;
	}

	.copy-btn-inline {
		flex-shrink: 0;
		padding: 0.25rem;
		background: transparent;
		border: none;
		color: var(--color-divine-text-tertiary);
		cursor: pointer;
		border-radius: 4px;
		transition: all 0.2s;
	}

	.copy-btn-inline:hover {
		color: var(--color-divine-green);
		background: var(--color-divine-muted);
	}

	.app-actions {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px solid var(--color-divine-border);
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}

	.btn-copy-bunker {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.375rem 0.75rem;
		background: transparent;
		color: var(--color-divine-green);
		border: 1px solid var(--color-divine-green);
		border-radius: 9999px;
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-copy-bunker:hover {
		background: var(--color-divine-green);
		color: #fff;
	}

	.btn-revoke {
		padding: 0.375rem 0.75rem;
		background: transparent;
		color: var(--color-divine-error);
		border: 1px solid var(--color-divine-error);
		border-radius: 9999px;
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
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		overflow: hidden;
	}

	.team-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
		color: var(--color-divine-text);
		text-decoration: none;
		transition: background 0.2s;
	}

	.team-item:last-child {
		border-bottom: none;
	}

	.team-item:hover {
		background: var(--color-divine-muted);
	}

	.team-info {
		min-width: 0;
	}

	.team-name {
		font-weight: 500;
		margin: 0;
	}

	.team-meta {
		color: var(--color-divine-text-tertiary);
		font-size: 0.875rem;
		margin: 0.25rem 0 0 0;
	}

	.arrow-icon {
		color: var(--color-divine-text-tertiary);
		transition: all 0.2s;
	}

	.team-item:hover .arrow-icon {
		color: var(--color-divine-green);
		transform: translateX(4px);
	}

	/* Landing Page Styles */
	.landing-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem 1rem;
	}

	.landing-content {
		max-width: 480px;
		width: 100%;
		text-align: center;
	}

	.landing-logo {
		display: inline-flex;
		align-items: center;
		gap: 0.75rem;
		font-size: 1.75rem;
		font-weight: 700;
		color: var(--color-divine-green);
		text-decoration: none;
		margin-bottom: 2rem;
	}

	.landing-logo:hover {
		opacity: 0.9;
	}

	.landing-title {
		font-size: 2.5rem;
		font-weight: 700;
		color: var(--color-divine-text);
		margin: 0 0 0.5rem 0;
		line-height: 1.2;
	}

	.landing-subtitle {
		font-size: 1.125rem;
		color: var(--color-divine-text-secondary);
		margin: 0 0 2rem 0;
	}

	.landing-ctas {
		display: flex;
		gap: 1rem;
		justify-content: center;
		margin-bottom: 1.5rem;
	}

	.landing-divider {
		display: flex;
		align-items: center;
		gap: 1rem;
		color: var(--color-divine-text-tertiary);
		font-size: 0.875rem;
		margin-bottom: 1.5rem;
	}

	.landing-divider::before,
	.landing-divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--color-divine-border);
	}

	.nip07-button {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		width: 100%;
		max-width: 280px;
		padding: 0.75rem 1.25rem;
		background: var(--color-divine-muted);
		color: var(--color-divine-text);
		border: 1px solid var(--color-divine-border);
		border-radius: 9999px;
		font-size: 0.9rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
	}

	.nip07-button:hover {
		background: var(--color-divine-border);
	}

	.features-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 1.5rem;
		margin-top: 4rem;
	}

	@media (max-width: 640px) {
		.features-grid {
			grid-template-columns: 1fr;
			gap: 1rem;
		}

		.landing-title {
			font-size: 2rem;
		}

		.landing-ctas {
			flex-direction: column;
			align-items: center;
		}

		.landing-ctas .button {
			width: 100%;
			max-width: 280px;
		}
	}

	.feature-card {
		text-align: center;
		padding: 1.5rem 1rem;
	}

	.feature-icon {
		width: 48px;
		height: 48px;
		background: color-mix(in srgb, var(--color-divine-green) 15%, transparent);
		border-radius: 12px;
		display: flex;
		align-items: center;
		justify-content: center;
		margin: 0 auto 1rem;
		color: var(--color-divine-green);
	}

	.feature-card h3 {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-divine-text);
		margin: 0 0 0.5rem 0;
	}

	.feature-card p {
		font-size: 0.875rem;
		color: var(--color-divine-text-secondary);
		margin: 0;
		line-height: 1.5;
	}

	.nostr-learn-more {
		margin-top: 2rem;
		font-size: 0.875rem;
		color: var(--color-divine-text-tertiary);
	}

	.nostr-learn-more a {
		color: var(--color-divine-green);
		text-decoration: none;
	}

	.nostr-learn-more a:hover {
		text-decoration: underline;
	}

	/* Revoke Modal Styles */
	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.6);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		backdrop-filter: blur(4px);
	}

	.modal {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 16px;
		padding: 1.5rem;
		max-width: 400px;
		width: 90%;
		box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
	}

	.modal h3 {
		margin: 0 0 1rem 0;
		color: var(--color-divine-text);
		font-size: 1.25rem;
		font-weight: 600;
	}

	.modal p {
		color: var(--color-divine-text-secondary);
		font-size: 0.95rem;
		margin: 0 0 0.5rem 0;
		line-height: 1.5;
	}

	.modal-warning {
		color: var(--color-divine-error);
		font-weight: 500;
	}

	.modal-actions {
		display: flex;
		gap: 0.75rem;
		margin-top: 1.5rem;
		justify-content: flex-end;
	}

	.btn-cancel {
		padding: 0.625rem 1.25rem;
		background: transparent;
		color: var(--color-divine-text-secondary);
		border: 1px solid var(--color-divine-border);
		border-radius: 9999px;
		cursor: pointer;
		font-size: 0.875rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.btn-cancel:hover {
		background: var(--color-divine-muted);
		color: var(--color-divine-text);
	}

	.btn-confirm-revoke {
		padding: 0.625rem 1.25rem;
		background: var(--color-divine-error);
		color: #fff;
		border: none;
		border-radius: 9999px;
		cursor: pointer;
		font-size: 0.875rem;
		font-weight: 600;
		transition: all 0.2s;
	}

	.btn-confirm-revoke:hover {
		background: #dc2626;
	}
</style>
