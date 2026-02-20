<script lang="ts">
import { getCurrentUser, setCurrentUser } from "$lib/current_user.svelte";
import { KeycastApi } from "$lib/keycast_api.svelte";
import { BRAND } from "$lib/brand";
import type { TeamWithRelations, BunkerSession } from "$lib/types";
import { Key, ArrowRight, PlusCircle, Gear, Copy, Check, EnvelopeSimple, CaretDown, CaretUp, Question, ArrowSquareOut, ShieldCheck, Export, PlugsConnected } from "phosphor-svelte";
import Loader from "$lib/components/Loader.svelte";
import CreateBunkerModal from "$lib/components/CreateBunkerModal.svelte";
import { onMount } from "svelte";
import { nip19 } from "nostr-tools";
import { toast } from "svelte-hot-french-toast";
import { signin, SigninMethod } from "$lib/utils/auth";
import { getAllowedPubkeys, isTeamsEnabled } from "$lib/utils/env";

interface GroupedSession {
	key: string;
	application_name: string;
	redirect_origin: string;
	isOAuth: boolean;
	total_activity: number;
	earliest_created: string;
	latest_activity: string | null;
	bunker_pubkeys: string[];
	sessions: BunkerSession[];
}

const api = new KeycastApi();
const currentUser = $derived(getCurrentUser());
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
let sessionToRevoke = $state<GroupedSession | null>(null);
let showLearnMore = $state(false);
let pubkeyFormat = $state<'hex' | 'npub'>('npub');
let copiedPubkey = $state<string | null>(null);
let isNip07Loading = $state(false);
let hasExtension = $state(false);
let adminRole = $state<string | null>(null);

const groupedSessions = $derived.by(() => {
	const groups = new Map<string, GroupedSession>();
	for (const session of sessions) {
		const isOAuth = !!session.redirect_origin?.trim();
		const key = isOAuth ? session.redirect_origin : session.bunker_pubkey;
		const existing = groups.get(key);
		if (existing) {
			existing.total_activity += session.activity_count;
			if (session.created_at < existing.earliest_created) {
				existing.earliest_created = session.created_at;
			}
			if (session.last_activity) {
				if (!existing.latest_activity || session.last_activity > existing.latest_activity) {
					existing.latest_activity = session.last_activity;
				}
			}
			existing.bunker_pubkeys.push(session.bunker_pubkey);
			existing.sessions.push(session);
		} else {
			groups.set(key, {
				key,
				application_name: session.application_name,
				redirect_origin: session.redirect_origin,
				isOAuth,
				total_activity: session.activity_count,
				earliest_created: session.created_at,
				latest_activity: session.last_activity,
				bunker_pubkeys: [session.bunker_pubkey],
				sessions: [session],
			});
		}
	}
	return [...groups.values()];
});

onMount(() => {
	hasExtension = typeof window !== 'undefined' && !!window.nostr;
});

async function handleNip07Signin() {
	isNip07Loading = true;
	try {
		await signin(SigninMethod.Nip07);
	} catch (err) {
		console.error('NIP-07 signin error:', err);
	} finally {
		isNip07Loading = false;
	}
}

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
	currentUser?.pubkey ? getAllowedPubkeys().includes(currentUser.pubkey) : false
);

async function loadTeams() {
	if (!currentUser?.pubkey) return;

	try {
		const response = await api.get<TeamWithRelations[]>('/teams');
		teams = response || [];
	} catch (err: any) {
		// 404 is expected for NIP-07 admins without user records
		if (err?.status !== 404) {
			console.error('Failed to load teams:', err);
		}
		teams = [];
	}
}

async function checkAdminStatus() {
	try {
		const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
		adminRole = response.is_admin ? response.role : null;
	} catch {
		adminRole = null;
	}
}

async function loadSessions() {
	if (!currentUser?.pubkey) return;

	try {
		const response = await api.get<{ sessions: BunkerSession[] }>('/user/sessions');
		sessions = response.sessions || [];
	} catch (err: any) {
		// 404 is expected for NIP-07 admins without user records
		if (err?.status !== 404) {
			console.error('Failed to load sessions:', err);
		}
		sessions = [];
	}
}

async function copyUserPubkey() {
	if (!currentUser) return;
	try {
		const formatted = formatPubkey(currentUser.pubkey);
		await navigator.clipboard.writeText(formatted);
		copiedNpub = true;
		toast.success(`${pubkeyFormat === 'npub' ? 'npub' : 'Hex pubkey'} copied!`);
		setTimeout(() => (copiedNpub = false), 2000);
	} catch (err) {
		toast.error('Failed to copy');
	}
}

function toggleSession(groupKey: string) {
	const newSet = new Set(expandedSessions);
	if (newSet.has(groupKey)) {
		newSet.delete(groupKey);
	} else {
		newSet.add(groupKey);
	}
	expandedSessions = newSet;
}

function formatDate(dateStr: string): string {
	const date = new Date(dateStr);
	return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function confirmRevoke(group: GroupedSession) {
	sessionToRevoke = group;
	showRevokeModal = true;
}

async function revokeGroupedSession(group: GroupedSession) {
	try {
		for (const pubkey of group.bunker_pubkeys) {
			await api.post('/user/sessions/revoke', { bunker_pubkey: pubkey });
		}
		toast.success(`Revoked access for ${group.application_name}`);
		showRevokeModal = false;
		sessionToRevoke = null;
		await loadSessions();
	} catch (err) {
		toast.error('Failed to revoke session');
	}
}

onMount(async () => {
	// Check for cookie-based authentication first
	if (!currentUser) {
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

	// Load dashboard if user is already set (e.g. cookie recovery above)
	await loadDashboardData();
});

async function loadDashboardData() {
	const user = getCurrentUser();
	if (!user?.pubkey) return;

	try {
		userNpub = nip19.npubEncode(user.pubkey);
	} catch (e) {
		userNpub = user.pubkey;
	}

	const loads: Promise<void>[] = [loadSessions()];
	if (isTeamsEnabled()) loads.push(loadTeams());
	loads.push(checkAdminStatus());
	await Promise.all(loads);
	isLoadingDashboard = false;
}

// Reactively load dashboard when user logs in after page mount (e.g. NIP-07)
$effect(() => {
	if (currentUser?.pubkey && isLoadingDashboard && !isCheckingAuth) {
		loadDashboardData();
	}
});
</script>

<svelte:head>
	<title>{currentUser ? 'Dashboard' : 'Welcome'} - {BRAND.name}</title>
</svelte:head>

{#if isCheckingAuth}
	<!-- Show loader while checking authentication -->
	<div class="flex items-center justify-center min-h-screen">
		<Loader />
	</div>
{:else if currentUser}
	<!-- Dashboard for authenticated users -->
	<div class="dashboard">
		{#if isLoadingDashboard}
			<Loader />
		{:else}
			<!-- Your Identity Section -->
			<section class="identity-section">
				<h2 class="section-title">
					{#if authMethod === 'nip07'}
						Admin Access
					{:else}
						Manage Your Identity
					{/if}
				</h2>
				<div class="identity-card">
					{#if authMethod === 'nip07'}
						<div class="identity-row">
							<div class="identity-icon">
								<PlugsConnected size={20} weight="fill" />
							</div>
							<div class="identity-info">
								<span class="identity-value">Signed in via NIP-07 extension</span>
								<span class="status-badge admin">Admin</span>
							</div>
						</div>
						<div class="identity-actions">
							<a href="/admin" class="identity-link">
								<Key size={16} />
								<span>Admin Dashboard</span>
							</a>
							<a href="/support-admin" class="identity-link">
								<ShieldCheck size={16} />
								<span>Support Tools</span>
							</a>
						</div>
					{:else if userEmail}
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
							<span class="identity-value mono" title={formatPubkey(currentUser.pubkey)}>
								{formatPubkey(currentUser.pubkey).slice(0, 12)}...{formatPubkey(currentUser.pubkey).slice(-8)}
							</span>
							<button class="copy-btn" onclick={copyUserPubkey} title="Copy pubkey">
								{#if copiedNpub}
									<Check size={16} />
								{:else}
									<Copy size={16} />
								{/if}
							</button>
							<button
								class="format-toggle-identity"
								onclick={() => pubkeyFormat = pubkeyFormat === 'hex' ? 'npub' : 'hex'}
								title="Switch between npub and hex format"
							>
								{pubkeyFormat === 'hex' ? 'npub' : 'hex'}
							</button>
							<a href="https://nostr.how/en/get-started" target="_blank" rel="noopener noreferrer" class="learn-link" title="What's an npub?">
								?
							</a>
						</div>
					</div>
					{#if authMethod === 'cookie'}
						<div class="identity-actions">
							{#if adminRole === 'full'}
								<a href="/admin" class="identity-link">
									<Key size={16} />
									<span>Admin Dashboard</span>
								</a>
							{/if}
							{#if adminRole === 'full' || adminRole === 'support'}
								<a href="/support-admin" class="identity-link">
									<ShieldCheck size={16} />
									<span>Support Tools</span>
								</a>
							{/if}
							<a href="/settings/security" class="identity-link">
								<Gear size={16} />
								<span>Security Settings</span>
							</a>
						</div>
					{/if}
				</div>
			</section>

			<!-- Learn More Section (not for NIP-07 admins) -->
			{#if authMethod !== 'nip07'}
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
							<p><strong>Your npub</strong> (public key) is like a username. Share it so others can find you across any Nostr app.</p>
							<p><strong>Your nsec</strong> (private key) proves you own this identity. Keep it safe! Find it in <a href="/settings/security">Security Settings</a> if you need to export it.</p>
						</div>

						<div class="learn-block">
							<h4><ShieldCheck size={16} weight="fill" /> Where Is Your Key?</h4>
							<p>When you sign up with email and password, diVine generates a Nostr key for you and stores it on <a href="https://login.divine.video" target="_blank" rel="noopener noreferrer">login.divine.video</a>, encrypted using the same standards banks and password managers rely on (<a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard" target="_blank" rel="noopener noreferrer">1</a>,<a href="https://cloud.google.com/security/products/security-key-management" target="_blank" rel="noopener noreferrer">2</a>). Your key is only decrypted in memory when an app needs to sign on your behalf, and is never stored in plain text.</p>
							<p>Any Nostr app that supports diVine Login, like <a href="https://privdm.com" target="_blank" rel="noopener noreferrer" class="inline-link">Priv DM <ArrowSquareOut size={12} /></a>, can use your identity with just your email and password. No copying keys between apps, no manual setup.</p>
						</div>

						<div class="learn-block">
							<h4><Key size={16} weight="fill" /> Already Have a Nostr Key?</h4>
							<p>You don't need a diVine account at all. Import your nsec into the diVine app and everything stays on your device.</p>
						</div>

						<div class="learn-block">
							<h4><Export size={16} weight="fill" /> Want Full Control of Your Key?</h4>
							<p>If you started with email and password but want full control, export your nsec from <a href="/settings/security">Security Settings</a> and move it to:</p>
							<ul class="learn-list">
								<li><strong>Your phone:</strong> <a href="https://primal.net" target="_blank" rel="noopener noreferrer" class="inline-link">Primal <ArrowSquareOut size={12} /></a> (iOS & Android), <a href="https://github.com/greenart7c3/Amber" target="_blank" rel="noopener noreferrer" class="inline-link">Amber <ArrowSquareOut size={12} /></a> (Android), or <a href="https://nsec.app" target="_blank" rel="noopener noreferrer" class="inline-link">nsec.app <ArrowSquareOut size={12} /></a> (any browser) turn your device into a personal signing server. When a Nostr app needs your signature, it asks your device and your key never leaves it.</li>
								<li><strong>Your browser:</strong> Extensions like <a href="https://getalby.com" target="_blank" rel="noopener noreferrer" class="inline-link">Alby <ArrowSquareOut size={12} /></a> or <a href="https://chromewebstore.google.com/detail/soapboxpub-signer/nnodjkgakfpkckcnbacpcjbpmlmbihdd" target="_blank" rel="noopener noreferrer" class="inline-link">Soapbox Signer <ArrowSquareOut size={12} /></a> (Chrome, Firefox) keep your key in the browser itself. <a href="https://apps.apple.com/app/nostash/id6499558903" target="_blank" rel="noopener noreferrer" class="inline-link">Nostash <ArrowSquareOut size={12} /></a> does the same for Safari on iOS.</li>
							</ul>
							<p>With these options, each app that needs your signature must connect to your signer individually. diVine Login handles that for you automatically.</p>
						</div>

						<div class="learn-block highlight">
							<h4><ShieldCheck size={16} weight="fill" /> Why This Matters</h4>
							<p>Unlike Twitter or Facebook, <strong>no company owns your Nostr identity</strong>. Even if diVine disappeared tomorrow, your identity and content would still exist on the network. Export your key and continue anywhere.</p>
							<p class="learn-cta">That's the power of Nostr.</p>
							<div class="learn-explore">
								<a href="https://nostrapps.com" target="_blank" rel="noopener noreferrer">Explore Nostr apps at nostrapps.com <ArrowSquareOut size={12} /></a>
							</div>
						</div>
					</div>
				{/if}
			</section>
			{/if}

			<!-- App Connections Section (not for NIP-07 admins) -->
			{#if authMethod !== 'nip07'}
			<section class="apps-section">
				<div class="section-header">
					<h2 class="section-title">App Connections</h2>
					<button class="btn-connect" onclick={() => (showCreateModal = true)}>
						<PlusCircle size={18} />
						<span>Connect to Nostr App</span>
					</button>
				</div>

				{#if groupedSessions.length === 0}
					<div class="empty-state">
						<p>No app connections yet.</p>
						<p class="hint">
							The diVine app and any app with "Sign in with diVine" already work with your email and password. Use this to connect to other Nostr apps. Browse them at <a href="https://nostrapps.com" target="_blank" rel="noopener noreferrer">nostrapps.com</a>.
						</p>
					</div>
				{:else}
					<div class="apps-list">
						{#each groupedSessions as group}
							{@const isExpanded = expandedSessions.has(group.key)}
							<div class="app-card" class:expanded={isExpanded}>
								<button class="app-header" onclick={() => toggleSession(group.key)}>
									<div class="app-info">
										<p class="app-name">
											{group.application_name}
											{#if group.isOAuth}
												<span class="connection-badge oauth">diVine Login</span>
											{:else}
												<span class="connection-badge manual">Bunker</span>
											{/if}
										</p>
										{#if group.isOAuth}<p class="app-domain">{group.redirect_origin}</p>{/if}
										<p class="app-meta">
											{new Date(group.earliest_created).toLocaleDateString()}
											{#if group.total_activity > 0}
												• {group.total_activity} {group.total_activity === 1 ? 'request' : 'requests'}
											{:else}
												• Not used yet
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
											{#if group.isOAuth}
												<div class="detail-item full-width">
													<span class="detail-label">Domain</span>
													<span class="detail-value">{group.redirect_origin}</span>
												</div>
												<div class="detail-item">
													<span class="detail-label">Created</span>
													<span class="detail-value">{formatDate(group.earliest_created)}</span>
												</div>
												<div class="detail-item">
													<span class="detail-label">Last Activity</span>
													<span class="detail-value">
														{group.latest_activity ? formatDate(group.latest_activity) : 'Never'}
													</span>
												</div>
												<div class="detail-item">
													<span class="detail-label">Total Requests</span>
													<span class="detail-value">{group.total_activity}</span>
												</div>
											{:else}
												{@const session = group.sessions[0]}
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
																onclick={(e) => { e.stopPropagation(); if (session.client_pubkey) copyPubkey(session.client_pubkey); }}
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
											{/if}
										</div>
										<div class="app-actions">
											<button
												class="btn-revoke"
												onclick={(e) => { e.stopPropagation(); confirmRevoke(group); }}
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
			{/if}

			<!-- Teams Section (only if teams feature is enabled and user has teams or is whitelisted) -->
			{#if isTeamsEnabled() && (teams.length > 0 || isWhitelisted)}
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
						onclick={() => sessionToRevoke && revokeGroupedSession(sessionToRevoke)}
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
				<img src="/divine-logo.svg" alt="{BRAND.shortName}" class="landing-logo-img" />
				<span class="landing-logo-sub">Login</span>
			</a>

			<h1 class="landing-title">One account for every Nostr app</h1>
			<p class="landing-subtitle">We handle your Nostr keys. You just use your email and password.</p>

			<!-- CTAs -->
			<div class="landing-ctas">
				<a href="/register" class="button button-primary">Get Started</a>
				<a href="/login" class="button button-secondary">Sign In</a>
			</div>

			<!-- NIP-07 Admin Login (only visible with browser extension) -->
			{#if hasExtension}
			<button
				class="admin-login-link"
				onclick={handleNip07Signin}
				disabled={isNip07Loading}
			>
				{isNip07Loading ? 'Connecting...' : 'Admin access with Nostr extension'}
			</button>
			{/if}

			<!-- Feature sections -->
			<div class="features-grid">
				<div class="feature-card">
					<div class="feature-icon">
						<EnvelopeSimple size={24} weight="fill" />
					</div>
					<h3>Just email and password</h3>
					<p>No technical setup. Create an account like you would on any other service.</p>
				</div>

				<div class="feature-card">
					<div class="feature-icon">
						<PlugsConnected size={24} weight="fill" />
					</div>
					<h3>Works across apps</h3>
					<p>Sign in to any Nostr app that supports diVine Login. One account, everywhere.</p>
				</div>

				<div class="feature-card">
					<div class="feature-icon">
						<ShieldCheck size={24} weight="fill" />
					</div>
					<h3>Secure by default</h3>
					<p>Your keys are encrypted and stored safely, like your passwords in iCloud or Google.</p>
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
		margin-bottom: 2rem;
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

	@media (max-width: 480px) {
		.identity-info {
			flex-wrap: wrap;
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

	.status-badge.admin {
		background: color-mix(in srgb, var(--color-divine-purple, #8b5cf6) 20%, transparent);
		color: var(--color-divine-purple, #8b5cf6);
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

	.format-toggle-identity {
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

	.format-toggle-identity:hover {
		background: var(--color-divine-green-muted);
		color: var(--color-divine-green);
		border-color: var(--color-divine-green);
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
		display: flex;
		flex-wrap: wrap;
		gap: 0.75rem 1.25rem;
		padding-top: 0.75rem;
		margin-top: 0;
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

	.learn-block p strong {
		color: var(--color-divine-text);
	}

	.learn-list {
		margin: 0.5rem 0 0 0;
		padding-left: 1.25rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.85rem;
		line-height: 1.8;
	}

	.learn-list li {
		margin-bottom: 0.5rem;
	}

	.learn-list a {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
	}

	.inline-link {
		white-space: nowrap;
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

	.learn-explore {
		margin-top: 0.75rem;
		padding-top: 0.75rem;
		border-top: 1px solid color-mix(in srgb, var(--color-divine-green) 15%, transparent);
	}

	.learn-explore a {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		color: var(--color-divine-green);
		text-decoration: none;
		font-size: 0.85rem;
		font-weight: 500;
	}

	.learn-explore a:hover {
		text-decoration: underline;
	}

	/* App Connections Section */
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

	.connection-badge {
		display: inline-block;
		font-size: 0.65rem;
		font-weight: 500;
		padding: 0.125rem 0.5rem;
		border-radius: 9999px;
		margin-left: 0.5rem;
		vertical-align: middle;
		letter-spacing: 0.02em;
	}

	.connection-badge.oauth {
		background: color-mix(in srgb, var(--color-divine-green) 15%, transparent);
		color: var(--color-divine-green);
		border: 1px solid color-mix(in srgb, var(--color-divine-green) 30%, transparent);
	}

	.connection-badge.manual {
		background: color-mix(in srgb, var(--color-divine-text-tertiary) 10%, transparent);
		color: var(--color-divine-text-secondary);
		border: 1px solid color-mix(in srgb, var(--color-divine-text-tertiary) 25%, transparent);
	}

	.app-domain {
		color: var(--color-divine-text-tertiary);
		font-size: 0.75rem;
		margin: 0.125rem 0 0 0;
		opacity: 0.7;
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

	:global(.arrow-icon) {
		color: var(--color-divine-text-tertiary);
		transition: all 0.2s;
	}

	.team-item:hover :global(.arrow-icon) {
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
		flex-direction: column;
		align-items: center;
		gap: 2px;
		text-decoration: none;
		margin-bottom: 2rem;
	}

	.landing-logo:hover {
		opacity: 0.85;
	}

	.landing-logo-img {
		height: 36px;
	}

	.landing-logo-sub {
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 12px;
		letter-spacing: 3px;
		text-transform: uppercase;
		color: var(--color-divine-green);
		opacity: 0.6;
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

	.admin-login-link {
		background: none;
		border: none;
		color: var(--color-divine-text-tertiary);
		font-size: 0.8rem;
		cursor: pointer;
		padding: 0.25rem 0.5rem;
		transition: color 0.2s;
	}

	.admin-login-link:hover:not(:disabled) {
		color: var(--color-divine-green);
	}

	.admin-login-link:disabled {
		opacity: 0.6;
		cursor: not-allowed;
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
