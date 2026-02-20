<script lang="ts">
	import { onMount } from 'svelte';
	import { BRAND } from '$lib/brand';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { goto } from '$app/navigation';
	import Loader from '$lib/components/Loader.svelte';
	import { ShieldCheck, Warning, MagnifyingGlass, User, Key, Calendar, Globe, Copy, Check, CheckCircle, XCircle, Link } from 'phosphor-svelte';
	import { nip19 } from 'nostr-tools';
	import { toast } from 'svelte-hot-french-toast';

	const api = new KeycastApi();

	let status = $state<'loading' | 'not-admin' | 'ready'>('loading');
	let adminRole = $state<string | null>(null);

	// User lookup state
	let searchQuery = $state('');
	let isSearching = $state(false);
	let searchResult = $state<null | { found: boolean; user?: UserDetails }>(null);
	let searchError = $state('');

	// Pubkey display state
	let pubkeyFormat = $state<'hex' | 'npub'>('npub');
	let copiedPubkey = $state(false);

	// Claim link state
	let claimToken = $state<{ claim_url: string; expires_at: string } | null>(null);
	let isLoadingClaimToken = $state(false);
	let isGeneratingClaimToken = $state(false);
	let copiedClaimUrl = $state(false);

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
		last_active: string | null;
	}

	onMount(async () => {
		// Verify admin status via API (uses keycast_session cookie directly)
		try {
			const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
			if (!response.is_admin) {
				status = 'not-admin';
				return;
			}
			adminRole = response.role;
		} catch {
			goto('/login?redirect=/support-admin', { replaceState: true });
			return;
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

	function truncateFormatted(hexPubkey: string): string {
		const formatted = formatPubkey(hexPubkey);
		if (formatted.length <= 20) return formatted;
		return formatted.slice(0, 12) + '...' + formatted.slice(-8);
	}

	async function copyPubkey(hexPubkey: string) {
		try {
			await navigator.clipboard.writeText(formatPubkey(hexPubkey));
			copiedPubkey = true;
			toast.success(`${pubkeyFormat === 'npub' ? 'npub' : 'Hex pubkey'} copied!`);
			setTimeout(() => (copiedPubkey = false), 2000);
		} catch {
			toast.error('Failed to copy');
		}
	}

	async function loadClaimToken(pubkey: string) {
		isLoadingClaimToken = true;
		claimToken = null;
		try {
			const result = await api.get<{ has_token: boolean; claim_url?: string; expires_at?: string }>(
				`/admin/claim-tokens?pubkey=${encodeURIComponent(pubkey)}`
			);
			if (result.has_token && result.claim_url && result.expires_at) {
				claimToken = { claim_url: result.claim_url, expires_at: result.expires_at };
			}
		} catch {
			// Silently ignore - user may not have claim token access
		} finally {
			isLoadingClaimToken = false;
		}
	}

	async function generateClaimToken(vineId: string) {
		isGeneratingClaimToken = true;
		try {
			const result = await api.post<{ claim_url: string; expires_at: string }>(
				'/admin/claim-tokens',
				{ vine_id: vineId }
			);
			claimToken = result;
			toast.success('Claim link generated');
		} catch (err: any) {
			toast.error(err.message || 'Failed to generate claim link');
		} finally {
			isGeneratingClaimToken = false;
		}
	}

	async function copyClaimUrl() {
		if (!claimToken) return;
		try {
			await navigator.clipboard.writeText(claimToken.claim_url);
			copiedClaimUrl = true;
			toast.success('Claim URL copied!');
			setTimeout(() => (copiedClaimUrl = false), 2000);
		} catch {
			toast.error('Failed to copy');
		}
	}

	$effect(() => {
		if (searchResult?.found && searchResult.user?.vine_id && !searchResult.user?.email) {
			loadClaimToken(searchResult.user.pubkey);
		} else {
			claimToken = null;
		}
	});
</script>

<svelte:head>
	<title>Support Admin - {BRAND.name}</title>
</svelte:head>

<div class="support-page">
	{#if status === 'loading'}
		<div class="status-card">
			<Loader />
			<p class="status-text">Checking admin status...</p>
		</div>
	{:else if status === 'not-admin'}
		<div class="status-card error">
			<Warning size={32} weight="fill" />
			<h2>Access Denied</h2>
			<p>Your account does not have support admin privileges.</p>
		</div>
	{:else if status === 'ready'}
		<div class="admin-header">
			<div class="admin-identity">
				<ShieldCheck size={20} weight="fill" />
				<span class="admin-label">Support Admin</span>
				<span class="admin-badge">{adminRole === 'full' ? 'Full Admin' : 'Support'}</span>
			</div>
		</div>

		<div class="tools-section">
			<h2>User Lookup</h2>
			<form class="search-form" onsubmit={(e) => { e.preventDefault(); searchUser(); }}>
				<div class="search-input-wrap">
					<MagnifyingGlass size={18} />
					<input
						type="text"
						bind:value={searchQuery}
						placeholder="Search for a user..."
						class="search-input"
						disabled={isSearching}
					/>
				</div>
				<button type="submit" class="btn-search" disabled={isSearching || !searchQuery.trim()}>
					{isSearching ? 'Searching...' : 'Search'}
				</button>
			</form>
			<p class="search-hint">Search by email, Vine username, vine_id, hex pubkey, or npub</p>

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
							<div class="user-header-info">
								<span class="user-name">{u.email || u.display_name || u.username || truncateFormatted(u.pubkey)}</span>
								{#if u.email}
									<span class="user-sub mono">
										<Key size={12} />
										<span title={formatPubkey(u.pubkey)}>{truncateFormatted(u.pubkey)}</span>
									</span>
								{/if}
							</div>
						</div>

						<div class="status-strip">
							<div class="status-item" class:status-ok={u.email_verified} class:status-warn={u.email && !u.email_verified} class:status-none={!u.email}>
								{#if u.email_verified}
									<CheckCircle size={14} weight="fill" />
									<span>Email verified</span>
								{:else if u.email}
									<XCircle size={14} weight="fill" />
									<span>Email unverified</span>
								{:else}
									<span class="status-neutral">No email</span>
								{/if}
							</div>
							<div class="status-item" class:status-ok={u.active_sessions > 0} class:status-none={u.active_sessions === 0}>
								<span>{u.active_sessions} active {u.active_sessions === 1 ? 'session' : 'sessions'}</span>
							</div>
						</div>

						<div class="user-fields">
							<div class="field">
								<span class="field-label"><Key size={14} /> Pubkey</span>
								<span class="field-value mono">
									<span title={formatPubkey(u.pubkey)}>{truncateFormatted(u.pubkey)}</span>
									<button class="icon-btn" onclick={() => copyPubkey(u.pubkey)} title="Copy pubkey">
										{#if copiedPubkey}
											<Check size={14} />
										{:else}
											<Copy size={14} />
										{/if}
									</button>
									<button
										class="format-toggle"
										onclick={() => pubkeyFormat = pubkeyFormat === 'hex' ? 'npub' : 'hex'}
										title="Switch between npub and hex format"
									>
										{pubkeyFormat === 'hex' ? 'npub' : 'hex'}
									</button>
								</span>
							</div>

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
								<span class="field-label"><Calendar size={14} /> Created</span>
								<span class="field-value">{formatDate(u.created_at)}</span>
							</div>

							<div class="field">
								<span class="field-label"><Calendar size={14} /> Last active</span>
								<span class="field-value">{u.last_active ? formatDate(u.last_active) : 'Never'}</span>
							</div>
						</div>

						{#if u.vine_id && !u.email}
							<div class="claim-section">
								<div class="claim-header">
									<Link size={16} />
									<span class="claim-title">Claim Link</span>
								</div>
								{#if isLoadingClaimToken}
									<p class="claim-loading">Checking for existing claim link...</p>
								{:else if claimToken}
									<div class="claim-url-display">
										<div class="claim-url-row">
											<input
												type="text"
												value={claimToken.claim_url}
												readonly
												class="claim-url-input"
											/>
											<button class="icon-btn" onclick={copyClaimUrl} title="Copy claim URL">
												{#if copiedClaimUrl}
													<Check size={14} />
												{:else}
													<Copy size={14} />
												{/if}
											</button>
										</div>
										<span class="claim-expiry">
											Expires {formatDate(claimToken.expires_at)}
										</span>
									</div>
								{:else}
									<button
										class="btn-generate-claim"
										onclick={() => generateClaimToken(u.vine_id!)}
										disabled={isGeneratingClaimToken}
									>
										{isGeneratingClaimToken ? 'Generating...' : 'Generate Claim Link'}
									</button>
								{/if}
							</div>
						{/if}
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

<style>
	.support-page {
		max-width: 560px;
		margin: 0 auto;
		padding: 2rem 1rem;
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

	.admin-label {
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

	.search-hint {
		font-size: 0.725rem;
		color: var(--color-divine-text-tertiary);
		margin: -0.5rem 0 1rem 0.25rem;
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
		gap: 0.625rem;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
		color: var(--color-divine-green);
	}

	.user-header-info {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
		min-width: 0;
	}

	.user-name {
		color: var(--color-divine-text);
		font-weight: 600;
		font-size: 1rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.user-sub {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		color: var(--color-divine-text-tertiary);
		font-size: 0.725rem;
	}

	.status-strip {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem 1rem;
		padding: 0.75rem 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
		background: var(--color-divine-muted);
	}

	.status-item {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		font-size: 0.75rem;
		font-weight: 500;
	}

	.status-item + .status-item {
		padding-left: 1rem;
		border-left: 1px solid var(--color-divine-border);
	}

	.status-item.status-ok {
		color: var(--color-divine-green);
	}

	.status-item.status-warn {
		color: var(--color-divine-warning);
	}

	.status-item.status-none {
		color: var(--color-divine-text-tertiary);
	}

	.status-neutral {
		color: var(--color-divine-text-tertiary);
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

	.icon-btn {
		background: transparent;
		border: none;
		color: var(--color-divine-text-tertiary);
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 4px;
		transition: all 0.2s;
		flex-shrink: 0;
	}

	.icon-btn:hover {
		color: var(--color-divine-green);
		background: var(--color-divine-muted);
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
		flex-shrink: 0;
	}

	.format-toggle:hover {
		background: color-mix(in srgb, var(--color-divine-green) 15%, transparent);
		color: var(--color-divine-green);
	}

	/* Claim link section */
	.claim-section {
		padding: 0.75rem 1.25rem;
		border-top: 1px solid var(--color-divine-border);
		background: color-mix(in srgb, var(--color-divine-green) 5%, var(--color-divine-surface));
	}

	.claim-header {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		color: var(--color-divine-green);
		margin-bottom: 0.5rem;
	}

	.claim-title {
		font-size: 0.825rem;
		font-weight: 600;
		color: var(--color-divine-text);
	}

	.claim-loading {
		font-size: 0.8rem;
		color: var(--color-divine-text-tertiary);
		margin: 0;
	}

	.claim-url-display {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.claim-url-row {
		display: flex;
		gap: 0.375rem;
		align-items: center;
	}

	.claim-url-input {
		flex: 1;
		padding: 0.5rem 0.625rem;
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: 6px;
		color: var(--color-divine-text);
		font-family: var(--font-mono);
		font-size: 0.725rem;
		outline: none;
	}

	.claim-expiry {
		font-size: 0.725rem;
		color: var(--color-divine-text-tertiary);
	}

	.btn-generate-claim {
		padding: 0.5rem 1rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 6px;
		font-size: 0.825rem;
		font-weight: 600;
		cursor: pointer;
		transition: opacity 0.2s;
	}

	.btn-generate-claim:hover:not(:disabled) {
		opacity: 0.9;
	}

	.btn-generate-claim:disabled {
		opacity: 0.5;
		cursor: not-allowed;
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
