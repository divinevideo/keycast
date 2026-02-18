<script lang="ts">
	import { onMount } from 'svelte';
	import { BRAND } from '$lib/brand';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { getCurrentUser } from '$lib/current_user.svelte';
	import { hasCfAccessCookie, cloudflareLogin } from '$lib/utils/auth';
	import { signout } from '$lib/utils/auth';
	import { goto } from '$app/navigation';
	import Loader from '$lib/components/Loader.svelte';
	import { ShieldCheck, SignOut, Warning, MagnifyingGlass, User, Key, Envelope, Calendar, Globe } from 'phosphor-svelte';

	const api = new KeycastApi();

	let status = $state<'loading' | 'no-cookie' | 'login-failed' | 'not-admin' | 'ready'>('loading');
	let cfEmail = $state('');
	let adminRole = $state<string | null>(null);

	// User lookup state
	let searchQuery = $state('');
	let isSearching = $state(false);
	let searchResult = $state<null | { found: boolean; user?: UserDetails }>(null);
	let searchError = $state('');

	interface UserDetails {
		pubkey: string;
		email: string | null;
		email_verified: boolean | null;
		username: string | null;
		display_name: string | null;
		vine_id: string | null;
		has_personal_key: boolean;
		active_sessions: number;
		created_at: string;
		updated_at: string;
	}

	onMount(async () => {
		if (!hasCfAccessCookie()) {
			status = 'no-cookie';
			return;
		}

		// Exchange CF JWT for UCAN session
		const pubkey = await cloudflareLogin();
		if (!pubkey) {
			status = 'login-failed';
			return;
		}

		// Verify admin status
		try {
			const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
			if (!response.is_admin) {
				status = 'not-admin';
				return;
			}
			adminRole = response.role;
		} catch {
			status = 'not-admin';
			return;
		}

		// Fetch email from auth status
		try {
			const authResponse = await fetch('/api/oauth/auth-status', { credentials: 'include' });
			if (authResponse.ok) {
				const data = await authResponse.json();
				if (data.email) cfEmail = data.email;
			}
		} catch {
			// Email display is optional
		}

		status = 'ready';
	});

	async function searchUser() {
		const q = searchQuery.trim();
		if (!q) return;

		isSearching = true;
		searchError = '';
		searchResult = null;

		try {
			const result = await api.get<{ found: boolean; user?: UserDetails }>(
				`/admin/user-lookup?q=${encodeURIComponent(q)}`
			);
			searchResult = result;
		} catch (err: any) {
			searchError = err.message || 'Search failed';
		} finally {
			isSearching = false;
		}
	}

	function formatDate(iso: string): string {
		return new Date(iso).toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	}

	function truncatePubkey(pk: string): string {
		if (pk.length <= 16) return pk;
		return pk.slice(0, 8) + '...' + pk.slice(-8);
	}
</script>

<svelte:head>
	<title>Support Admin - {BRAND.name}</title>
</svelte:head>

<div class="support-page">
	<div class="support-container">
		<a href="/" class="support-branding">
			<img src="/divine-logo.svg" alt={BRAND.shortName} class="support-logo-img" />
			<span class="support-logo-sub">Support Admin</span>
		</a>

		{#if status === 'loading'}
			<div class="status-card">
				<Loader />
				<p class="status-text">Authenticating via Cloudflare Access...</p>
			</div>
		{:else if status === 'no-cookie'}
			<div class="status-card error">
				<Warning size={32} weight="fill" />
				<h2>Cloudflare Access Required</h2>
				<p>This page is protected by Cloudflare Access. You should be redirected to SSO automatically.</p>
				<p class="hint">If you're not redirected, check that Cloudflare Access is configured for this path.</p>
			</div>
		{:else if status === 'login-failed'}
			<div class="status-card error">
				<Warning size={32} weight="fill" />
				<h2>Authentication Failed</h2>
				<p>Your Cloudflare Access session could not be validated by the server.</p>
				<p class="hint">Try clearing your cookies and signing in again through Cloudflare Access.</p>
			</div>
		{:else if status === 'not-admin'}
			<div class="status-card error">
				<Warning size={32} weight="fill" />
				<h2>Access Denied</h2>
				<p>Your account does not have admin privileges. Contact the team to get access.</p>
			</div>
		{:else if status === 'ready'}
			<div class="admin-header">
				<div class="admin-identity">
					<ShieldCheck size={20} weight="fill" />
					<span class="admin-email">{cfEmail || 'Support Admin'}</span>
					<span class="admin-badge">{adminRole === 'full' ? 'Full Admin' : 'Support'}</span>
				</div>
				<button class="btn-signout" onclick={signout}>
					<SignOut size={16} />
					Sign Out
				</button>
			</div>

			<div class="tools-section">
				<h2>User Lookup</h2>
				<form class="search-form" onsubmit={(e) => { e.preventDefault(); searchUser(); }}>
					<div class="search-input-wrap">
						<MagnifyingGlass size={18} />
						<input
							type="text"
							bind:value={searchQuery}
							placeholder="Email address, hex pubkey, or npub..."
							class="search-input"
							disabled={isSearching}
						/>
					</div>
					<button type="submit" class="btn-search" disabled={isSearching || !searchQuery.trim()}>
						{isSearching ? 'Searching...' : 'Search'}
					</button>
				</form>

				{#if searchError}
					<div class="search-error">
						<Warning size={16} />
						<span>{searchError}</span>
					</div>
				{/if}

				{#if searchResult}
					{#if !searchResult.found}
						<div class="no-result">
							<p>No user found matching that query.</p>
						</div>
					{:else if searchResult.user}
						{@const u = searchResult.user}
						<div class="user-card">
							<div class="user-card-header">
								<User size={20} weight="fill" />
								<span class="user-name">{u.display_name || u.username || truncatePubkey(u.pubkey)}</span>
							</div>

							<div class="user-fields">
								<div class="field">
									<span class="field-label"><Key size={14} /> Pubkey</span>
									<span class="field-value mono">{u.pubkey}</span>
								</div>

								{#if u.email}
									<div class="field">
										<span class="field-label"><Envelope size={14} /> Email</span>
										<span class="field-value">
											{u.email}
											{#if u.email_verified}
												<span class="badge verified">verified</span>
											{:else}
												<span class="badge unverified">unverified</span>
											{/if}
										</span>
									</div>
								{/if}

								{#if u.username}
									<div class="field">
										<span class="field-label"><User size={14} /> Username</span>
										<span class="field-value">{u.username}</span>
									</div>
								{/if}

								{#if u.vine_id}
									<div class="field">
										<span class="field-label"><Globe size={14} /> Vine ID</span>
										<span class="field-value">{u.vine_id}</span>
									</div>
								{/if}

								<div class="field">
									<span class="field-label">Personal Key</span>
									<span class="field-value">{u.has_personal_key ? 'Yes' : 'No'}</span>
								</div>

								<div class="field">
									<span class="field-label">Active Sessions</span>
									<span class="field-value">{u.active_sessions}</span>
								</div>

								<div class="field">
									<span class="field-label"><Calendar size={14} /> Created</span>
									<span class="field-value">{formatDate(u.created_at)}</span>
								</div>

								<div class="field">
									<span class="field-label"><Calendar size={14} /> Updated</span>
									<span class="field-value">{formatDate(u.updated_at)}</span>
								</div>
							</div>
						</div>
					{/if}
				{/if}
			</div>

			{#if adminRole === 'full'}
				<div class="tools-section">
					<h2>Quick Links</h2>
					<div class="links-grid">
						<a href="/admin" class="link-card">
							<span class="link-title">Full Admin Dashboard</span>
							<span class="link-desc">API tokens, preloaded accounts, claim links</span>
						</a>
					</div>
				</div>
			{/if}
		{/if}
	</div>
</div>

<style>
	.support-page {
		min-height: 100vh;
		display: flex;
		align-items: flex-start;
		justify-content: center;
		padding: 4rem 1rem 2rem;
		background: var(--color-divine-bg);
	}

	.support-container {
		max-width: 560px;
		width: 100%;
	}

	.support-branding {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 2px;
		text-decoration: none;
		margin-bottom: 2rem;
	}

	.support-branding:hover {
		opacity: 0.85;
	}

	.support-logo-img {
		height: 28px;
	}

	.support-logo-sub {
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 11px;
		letter-spacing: 3px;
		text-transform: uppercase;
		color: var(--color-divine-purple, #8b5cf6);
		opacity: 0.7;
	}

	.status-card {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 2.5rem 1.5rem;
		text-align: center;
	}

	.status-card.error {
		border-color: color-mix(in srgb, var(--color-divine-error) 40%, var(--color-divine-border));
		color: var(--color-divine-error);
	}

	.status-card h2 {
		color: var(--color-divine-text);
		font-size: 1.25rem;
		font-weight: 600;
		margin: 1rem 0 0.5rem;
	}

	.status-card p {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		margin: 0 0 0.5rem;
		line-height: 1.5;
	}

	.status-card .hint {
		font-size: 0.825rem;
		color: var(--color-divine-text-tertiary);
	}

	.status-text {
		color: var(--color-divine-text-secondary);
		margin-top: 1rem;
		font-size: 0.9rem;
	}

	.admin-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 1rem 1.25rem;
		margin-bottom: 1.5rem;
	}

	.admin-identity {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--color-divine-green);
	}

	.admin-email {
		color: var(--color-divine-text);
		font-size: 0.9rem;
		font-weight: 500;
	}

	.admin-badge {
		font-size: 0.7rem;
		font-weight: 500;
		padding: 0.125rem 0.5rem;
		border-radius: 9999px;
		background: color-mix(in srgb, var(--color-divine-purple, #8b5cf6) 20%, transparent);
		color: var(--color-divine-purple, #8b5cf6);
	}

	.btn-signout {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.375rem 0.75rem;
		background: transparent;
		border: 1px solid var(--color-divine-border);
		border-radius: 9999px;
		color: var(--color-divine-text-secondary);
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-signout:hover {
		border-color: var(--color-divine-error);
		color: var(--color-divine-error);
	}

	.tools-section {
		margin-bottom: 1.5rem;
	}

	.tools-section h2 {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-divine-text);
		margin: 0 0 0.75rem;
	}

	/* Search form */
	.search-form {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.search-input-wrap {
		flex: 1;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 0.75rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 8px;
		color: var(--color-divine-text-secondary);
		transition: border-color 0.2s;
	}

	.search-input-wrap:focus-within {
		border-color: var(--color-divine-green);
	}

	.search-input {
		flex: 1;
		padding: 0.625rem 0;
		background: transparent;
		border: none;
		outline: none;
		color: var(--color-divine-text);
		font-size: 0.875rem;
	}

	.search-input::placeholder {
		color: var(--color-divine-text-tertiary);
	}

	.btn-search {
		padding: 0.625rem 1.25rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 8px;
		font-size: 0.85rem;
		font-weight: 600;
		cursor: pointer;
		transition: opacity 0.2s;
		white-space: nowrap;
	}

	.btn-search:hover:not(:disabled) {
		opacity: 0.9;
	}

	.btn-search:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.search-error {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1rem;
		background: color-mix(in srgb, var(--color-divine-error) 10%, var(--color-divine-bg));
		border: 1px solid color-mix(in srgb, var(--color-divine-error) 30%, transparent);
		border-radius: 8px;
		color: var(--color-divine-error);
		font-size: 0.85rem;
		margin-bottom: 1rem;
	}

	.no-result {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 1.5rem;
		text-align: center;
	}

	.no-result p {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		margin: 0;
	}

	/* User card */
	.user-card {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		overflow: hidden;
	}

	.user-card-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
		color: var(--color-divine-green);
	}

	.user-name {
		color: var(--color-divine-text);
		font-weight: 600;
		font-size: 1rem;
	}

	.user-fields {
		padding: 0.5rem 0;
	}

	.field {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 0.625rem 1.25rem;
		gap: 1rem;
	}

	.field:hover {
		background: var(--color-divine-muted);
	}

	.field-label {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.825rem;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.field-value {
		color: var(--color-divine-text);
		font-size: 0.85rem;
		text-align: right;
		word-break: break-all;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
		justify-content: flex-end;
	}

	.field-value.mono {
		font-family: var(--font-mono);
		font-size: 0.75rem;
	}

	.badge {
		font-size: 0.675rem;
		font-weight: 500;
		padding: 0.1rem 0.4rem;
		border-radius: 9999px;
	}

	.badge.verified {
		background: color-mix(in srgb, var(--color-divine-green) 20%, transparent);
		color: var(--color-divine-green);
	}

	.badge.unverified {
		background: color-mix(in srgb, var(--color-divine-warning) 20%, transparent);
		color: var(--color-divine-warning);
	}

	.links-grid {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.link-card {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		padding: 1rem 1.25rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		text-decoration: none;
		transition: all 0.2s;
	}

	.link-card:hover {
		border-color: var(--color-divine-green);
		background: var(--color-divine-muted);
	}

	.link-title {
		color: var(--color-divine-text);
		font-weight: 500;
		font-size: 0.9rem;
	}

	.link-desc {
		color: var(--color-divine-text-tertiary);
		font-size: 0.8rem;
	}
</style>
