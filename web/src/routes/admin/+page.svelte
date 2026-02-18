<script lang="ts">
	import { getCurrentUser } from '$lib/current_user.svelte';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';
	import { toast } from 'svelte-hot-french-toast';
	import { goto } from '$app/navigation';
	import { Copy, Check, Key, Terminal, Users, Link, Warning, ArrowSquareOut } from 'phosphor-svelte';
	import { getViteDomain } from '$lib/utils/env';

	const api = new KeycastApi();
	const currentUser = $derived(getCurrentUser());
	const user = $derived(currentUser);
	const serverUrl = getViteDomain();

	// Admin status from API (single source of truth)
	let isAdmin = $state<boolean | null>(null);
	let adminRole = $state<string | null>(null);
	let isCheckingAdmin = $state(true);

	// Check admin status when user is available
	$effect(() => {
		if (user?.pubkey && isAdmin === null) {
			checkAdminStatus();
		}
	});

	async function checkAdminStatus() {
		try {
			isCheckingAdmin = true;

			const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
			isAdmin = response.is_admin;
			adminRole = response.role;
			if (!response.is_admin) {
				toast.error('Admin access required');
				goto('/', { replaceState: true });
			} else if (response.role !== 'full') {
				// Support admins should use /support-admin
				goto('/support-admin', { replaceState: true });
			}
		} catch (err) {
			console.error('Failed to check admin status:', err);
			isAdmin = false;
			goto('/', { replaceState: true });
		} finally {
			isCheckingAdmin = false;
		}
	}

	// API Token state
	let adminToken = $state('');
	let tokenExpiresAt = $state('');
	let isGeneratingToken = $state(false);
	let copiedToken = $state(false);
	let showToken = $state(false);

	// Docs state
	let expandedDocs = $state<Set<string>>(new Set(['quickstart']));

	function toggleDocs(section: string) {
		if (expandedDocs.has(section)) {
			expandedDocs.delete(section);
		} else {
			expandedDocs.add(section);
		}
		expandedDocs = new Set(expandedDocs);
	}

	async function generateAdminToken() {
		try {
			isGeneratingToken = true;
			const response = await api.get<{ token: string; expires_at: string }>('/admin/token');
			adminToken = response.token;
			tokenExpiresAt = new Date(response.expires_at).toLocaleDateString('en-US', {
				year: 'numeric',
				month: 'long',
				day: 'numeric'
			});
			showToken = false;
			toast.success('Admin API token generated');
		} catch (err: any) {
			console.error('Failed to generate token:', err);
			toast.error(err.message || 'Failed to generate token');
		} finally {
			isGeneratingToken = false;
		}
	}

	async function copyToken() {
		if (!adminToken) return;
		try {
			await navigator.clipboard.writeText(adminToken);
			copiedToken = true;
			toast.success('Token copied to clipboard');
			setTimeout(() => (copiedToken = false), 2000);
		} catch {
			toast.error('Failed to copy');
		}
	}

	// Example code snippets
	const preloadUserExample = `curl -X POST ${serverUrl}/api/admin/preload-user \\
  -H "Authorization: Bearer \$ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "vine_id": "12345678",
    "username": "kingbach",
    "display_name": "KingBach"
  }'`;

	const signEventExample = `curl -X POST ${serverUrl}/api/nostr \\
  -H "Authorization: Bearer \$USER_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "method": "sign_event",
    "params": [{
      "kind": 1,
      "content": "Hello from import script!",
      "tags": [],
      "created_at": 1234567890,
      "pubkey": "<USER_PUBKEY>"
    }]
  }'`;

	const claimTokenExample = `curl -X POST ${serverUrl}/api/admin/claim-tokens \\
  -H "Authorization: Bearer \$ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"vine_id": "12345678"}'`;
</script>

<svelte:head>
	<title>Admin Dashboard - {BRAND.name}</title>
</svelte:head>

{#if !user || isCheckingAdmin}
	<div class="admin-page">
		<div class="loading">Loading...</div>
	</div>
{:else if !isAdmin}
	<div class="admin-page">
		<div class="access-denied">
			<Warning size={48} weight="fill" />
			<h2>Access Denied</h2>
			<p>Your account is not authorized for admin access.</p>
		</div>
	</div>
{:else}
	<div class="admin-page">
		<div class="header">
			<h1>Admin Dashboard</h1>
			<p class="subtitle">Manage preloaded accounts and generate API tokens for import scripts</p>
		</div>

		<!-- API Token Section -->
		<div class="section">
			<div class="section-header">
				<div class="section-icon"><Key size={24} weight="duotone" /></div>
				<div>
					<h2>API Token</h2>
					<p>Generate a long-lived admin token for use in import scripts</p>
				</div>
			</div>

			<div class="token-container">
				{#if adminToken}
					<div class="token-display">
						<div class="token-info">
							<span class="token-label">Your Admin Token</span>
							<span class="token-expiry">Expires: {tokenExpiresAt}</span>
						</div>
						<div class="token-field">
							<input
								type={showToken ? 'text' : 'password'}
								value={adminToken}
								readonly
								class="token-input"
							/>
							<button class="btn-icon" onclick={() => (showToken = !showToken)} title={showToken ? 'Hide' : 'Show'}>
								{showToken ? '🙈' : '👁️'}
							</button>
							<button class="btn-icon" onclick={copyToken} title="Copy">
								{#if copiedToken}
									<Check size={18} weight="bold" />
								{:else}
									<Copy size={18} />
								{/if}
							</button>
						</div>
						<div class="token-warning">
							<Warning size={16} />
							<span>Keep this token secure. It grants admin access for 30 days.</span>
						</div>
					</div>
				{/if}

				<button class="btn-primary" onclick={generateAdminToken} disabled={isGeneratingToken}>
					{isGeneratingToken ? 'Generating...' : adminToken ? 'Regenerate Token' : 'Generate Token'}
				</button>
			</div>
		</div>

		<!-- Documentation Section -->
		<div class="section docs-section">
			<div class="section-header">
				<div class="section-icon"><Terminal size={24} weight="duotone" /></div>
				<div>
					<h2>API Documentation</h2>
					<p>How to use the admin APIs for Vine user import</p>
				</div>
			</div>

			<!-- Quick Start -->
			<div class="doc-block">
				<button class="doc-header" onclick={() => toggleDocs('quickstart')}>
					<span>Quick Start Guide</span>
					<span class="doc-toggle">{expandedDocs.has('quickstart') ? '−' : '+'}</span>
				</button>
				{#if expandedDocs.has('quickstart')}
					<div class="doc-content">
						<p>The import workflow has three main steps:</p>
						<ol>
							<li><strong>Create preloaded user</strong> — Generate a Nostr keypair and get a signing token</li>
							<li><strong>Sign events</strong> — Use the token to sign Nostr events via HTTP RPC</li>
							<li><strong>Generate claim link</strong> — Create a link for the user to set their email/password</li>
						</ol>
						<p class="doc-note">
							The signing token is opaque — your script never sees the user's private key (nsec).
							All signing happens server-side through the <code>/api/nostr</code> endpoint.
						</p>
					</div>
				{/if}
			</div>

			<!-- Create Preloaded User -->
			<div class="doc-block">
				<button class="doc-header" onclick={() => toggleDocs('preload')}>
					<div class="doc-title">
						<Users size={18} />
						<span>POST /api/admin/preload-user</span>
					</div>
					<span class="doc-toggle">{expandedDocs.has('preload') ? '−' : '+'}</span>
				</button>
				{#if expandedDocs.has('preload')}
					<div class="doc-content">
						<p>Creates a new preloaded user with a generated Nostr keypair. Returns the user's pubkey and a signing token.</p>

						<h4>Request Body</h4>
						<table class="params-table">
							<tbody>
								<tr><td><code>vine_id</code></td><td>Unique identifier from source system (required)</td></tr>
								<tr><td><code>username</code></td><td>NIP-05 username, e.g. "kingbach" (required)</td></tr>
								<tr><td><code>display_name</code></td><td>Display name for UIs (optional)</td></tr>
							</tbody>
						</table>

						<h4>Response</h4>
						<table class="params-table">
							<tbody>
								<tr><td><code>pubkey</code></td><td>The user's Nostr public key (hex)</td></tr>
								<tr><td><code>token</code></td><td>Signing token for <code>/api/nostr</code> RPC</td></tr>
							</tbody>
						</table>

						<h4>Example</h4>
						<pre class="code-block">{preloadUserExample}</pre>
					</div>
				{/if}
			</div>

			<!-- Sign Events -->
			<div class="doc-block">
				<button class="doc-header" onclick={() => toggleDocs('sign')}>
					<div class="doc-title">
						<Key size={18} />
						<span>POST /api/nostr (sign_event)</span>
					</div>
					<span class="doc-toggle">{expandedDocs.has('sign') ? '−' : '+'}</span>
				</button>
				{#if expandedDocs.has('sign')}
					<div class="doc-content">
						<p>Sign a Nostr event on behalf of the preloaded user. Uses the token returned from <code>preload-user</code>.</p>

						<h4>Supported Methods</h4>
						<table class="params-table">
							<tbody>
								<tr><td><code>get_public_key</code></td><td>Returns the user's hex pubkey</td></tr>
								<tr><td><code>sign_event</code></td><td>Signs an unsigned event</td></tr>
								<tr><td><code>nip04_encrypt</code></td><td>Encrypts using NIP-04</td></tr>
								<tr><td><code>nip04_decrypt</code></td><td>Decrypts using NIP-04</td></tr>
								<tr><td><code>nip44_encrypt</code></td><td>Encrypts using NIP-44</td></tr>
								<tr><td><code>nip44_decrypt</code></td><td>Decrypts using NIP-44</td></tr>
							</tbody>
						</table>

						<h4>Example</h4>
						<pre class="code-block">{signEventExample}</pre>

						<p class="doc-note">
							The token expires after 30 days. Preloaded user tokens stop working once the user claims their account.
						</p>
					</div>
				{/if}
			</div>

			<!-- Generate Claim Link -->
			<div class="doc-block">
				<button class="doc-header" onclick={() => toggleDocs('claim')}>
					<div class="doc-title">
						<Link size={18} />
						<span>POST /api/admin/claim-tokens</span>
					</div>
					<span class="doc-toggle">{expandedDocs.has('claim') ? '−' : '+'}</span>
				</button>
				{#if expandedDocs.has('claim')}
					<div class="doc-content">
						<p>Generates a claim link for a preloaded user. Send this to the user so they can set their email and password.</p>

						<h4>Request Body</h4>
						<table class="params-table">
							<tbody>
								<tr><td><code>vine_id</code></td><td>The user's vine_id from preload-user</td></tr>
							</tbody>
						</table>

						<h4>Response</h4>
						<table class="params-table">
							<tbody>
								<tr><td><code>claim_url</code></td><td>URL to send to the user</td></tr>
								<tr><td><code>expires_at</code></td><td>Link expiration (7 days)</td></tr>
							</tbody>
						</table>

						<h4>Example</h4>
						<pre class="code-block">{claimTokenExample}</pre>

						<p class="doc-note">
							Claim links are single-use and expire after 7 days. You can generate new links for the same user if needed.
						</p>
					</div>
				{/if}
			</div>
		</div>

		<!-- Future Features Placeholder -->
		<div class="section future-section">
			<div class="section-header">
				<div class="section-icon">🚀</div>
				<div>
					<h2>Coming Soon</h2>
					<p>Additional admin features planned for future releases</p>
				</div>
			</div>
			<ul class="future-list">
				<li>Bulk user import via CSV</li>
				<li>User management dashboard</li>
				<li>Activity logs and analytics</li>
				<li>Claim link status tracking</li>
			</ul>
		</div>
	</div>
{/if}

<style>
	.admin-page {
		max-width: 900px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}

	.loading, .access-denied {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		min-height: 300px;
		color: var(--color-divine-text-secondary);
	}

	.access-denied h2 {
		margin: 1rem 0 0.5rem;
		color: var(--color-divine-error);
	}

	.header {
		margin-bottom: 2rem;
	}

	.header h1 {
		font-size: 1.5rem;
		font-weight: 600;
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-text);
	}

	.subtitle {
		color: var(--color-divine-text-secondary);
		font-size: 0.95rem;
		margin: 0;
	}

	.section {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 1.5rem;
		margin-bottom: 1.5rem;
	}

	.section-header {
		display: flex;
		gap: 1rem;
		align-items: flex-start;
		margin-bottom: 1.25rem;
	}

	.section-icon {
		width: 40px;
		height: 40px;
		background: color-mix(in srgb, var(--color-divine-green) 15%, var(--color-divine-bg));
		border-radius: 10px;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--color-divine-green);
		font-size: 1.25rem;
	}

	.section-header h2 {
		margin: 0 0 0.25rem 0;
		color: var(--color-divine-text);
		font-size: 1.125rem;
		font-weight: 600;
	}

	.section-header p {
		color: var(--color-divine-text-secondary);
		margin: 0;
		font-size: 0.875rem;
	}

	.token-container {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.token-display {
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: 8px;
		padding: 1rem;
	}

	.token-info {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.token-label {
		font-weight: 500;
		color: var(--color-divine-text);
		font-size: 0.875rem;
	}

	.token-expiry {
		font-size: 0.8rem;
		color: var(--color-divine-text-secondary);
	}

	.token-field {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.token-input {
		flex: 1;
		padding: 0.625rem 0.75rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 6px;
		color: var(--color-divine-text);
		font-family: var(--font-mono);
		font-size: 0.85rem;
	}

	.token-warning {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.75rem;
		padding: 0.625rem 0.75rem;
		background: color-mix(in srgb, var(--color-divine-warning) 10%, var(--color-divine-bg));
		border: 1px solid color-mix(in srgb, var(--color-divine-warning) 30%, transparent);
		border-radius: 6px;
		color: var(--color-divine-warning);
		font-size: 0.8rem;
	}

	.btn-icon {
		padding: 0.5rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 6px;
		cursor: pointer;
		color: var(--color-divine-text-secondary);
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.btn-icon:hover {
		background: var(--color-divine-border);
		color: var(--color-divine-text);
	}

	.btn-primary {
		padding: 0.75rem 1.5rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 9999px;
		font-size: 0.875rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
		align-self: flex-start;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--color-divine-green-dark);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* Documentation styles */
	.docs-section {
		background: var(--color-divine-surface);
	}

	.doc-block {
		border: 1px solid var(--color-divine-border);
		border-radius: 8px;
		margin-bottom: 0.75rem;
		overflow: hidden;
	}

	.doc-block:last-child {
		margin-bottom: 0;
	}

	.doc-header {
		width: 100%;
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.875rem 1rem;
		background: var(--color-divine-bg);
		border: none;
		cursor: pointer;
		color: var(--color-divine-text);
		font-size: 0.9rem;
		font-weight: 500;
		text-align: left;
		transition: background 0.2s;
	}

	.doc-header:hover {
		background: color-mix(in srgb, var(--color-divine-bg) 80%, var(--color-divine-border));
	}

	.doc-title {
		display: flex;
		align-items: center;
		gap: 0.625rem;
	}

	.doc-toggle {
		color: var(--color-divine-text-secondary);
		font-size: 1.25rem;
		font-weight: 300;
	}

	.doc-content {
		padding: 1rem;
		border-top: 1px solid var(--color-divine-border);
		font-size: 0.875rem;
		color: var(--color-divine-text-secondary);
		line-height: 1.6;
	}

	.doc-content p {
		margin: 0 0 1rem 0;
	}

	.doc-content ol {
		margin: 0 0 1rem 1.25rem;
	}

	.doc-content li {
		margin-bottom: 0.375rem;
	}

	.doc-content h4 {
		color: var(--color-divine-text);
		font-size: 0.8rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin: 1.25rem 0 0.625rem 0;
	}

	.doc-content h4:first-child {
		margin-top: 0;
	}

	.doc-note {
		padding: 0.75rem 1rem;
		background: color-mix(in srgb, var(--color-divine-green) 10%, var(--color-divine-bg));
		border-left: 3px solid var(--color-divine-green);
		border-radius: 0 6px 6px 0;
		font-size: 0.825rem;
		margin: 1rem 0 0 0 !important;
	}

	.params-table {
		width: 100%;
		border-collapse: collapse;
		margin: 0.5rem 0 1rem;
	}

	.params-table td {
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--color-divine-border);
		font-size: 0.825rem;
	}

	.params-table td:first-child {
		width: 140px;
		background: var(--color-divine-bg);
	}

	.code-block {
		background: #1a1a2e;
		color: #e2e8f0;
		padding: 1rem;
		border-radius: 8px;
		font-family: var(--font-mono);
		font-size: 0.8rem;
		overflow-x: auto;
		white-space: pre-wrap;
		word-break: break-all;
		margin: 0.5rem 0 0;
	}

	code {
		background: var(--color-divine-bg);
		padding: 0.125rem 0.375rem;
		border-radius: 4px;
		font-family: var(--font-mono);
		font-size: 0.85em;
	}

	/* Future features */
	.future-section {
		border-style: dashed;
		opacity: 0.8;
	}

	.future-list {
		margin: 0;
		padding-left: 1.25rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
	}

	.future-list li {
		margin-bottom: 0.5rem;
	}
</style>
