<script lang="ts">
	import { getCurrentUser } from '$lib/current_user.svelte';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';
	import ndk from '$lib/ndk.svelte';
	import { NDKNip07Signer } from '@nostr-dev-kit/ndk';
	import { toast } from 'svelte-hot-french-toast';
	import type { BunkerSession } from '$lib/types';
	import CreateBunkerModal from '$lib/components/CreateBunkerModal.svelte';

	const api = new KeycastApi();
	const currentUser = $derived(getCurrentUser());
	const user = $derived(currentUser?.user);

	let sessions = $state<BunkerSession[]>([]);
	let isLoading = $state(true);
	let error = $state('');
	let showRevokeModal = $state(false);
	let selectedSession = $state<BunkerSession | null>(null);
	let showCreateModal = $state(false);

	async function loadSessions() {
		try {
			isLoading = true;
			error = '';

			let authHeaders: Record<string, string> = {};

			// If NIP-07 user, build NIP-98 auth event
			if (user?.pubkey && ndk.signer) {
				const authEvent = await api.buildUnsignedAuthEvent('/user/sessions', 'GET', user.pubkey);
				await authEvent?.sign();
				authHeaders.Authorization = `Nostr ${btoa(JSON.stringify(authEvent))}`;
			}
			// Otherwise backend will use HttpOnly cookie (sent automatically with credentials: 'include')

			const response = await api.get<{ sessions: BunkerSession[] }>('/user/sessions', {
				headers: authHeaders
			});

			sessions = response.sessions;
		} catch (err: any) {
			// Check if it's an auth error
			if (err.message?.includes('401') || err.message?.includes('Unauthorized')) {
				error = 'Not authenticated. Please sign in with email/password or NIP-07 browser extension.';
			} else {
				error = `Failed to load sessions: ${err}`;
			}
			console.error('Load sessions error:', err);
		} finally {
			isLoading = false;
		}
	}

	async function revokeSession(secret: string) {
		try {
			let authHeaders: Record<string, string> = {};

			// If NIP-07 user, build NIP-98 auth event
			if (user?.pubkey && ndk.signer) {
				const body = JSON.stringify({ secret });
				const authEvent = await api.buildUnsignedAuthEvent(
					'/user/sessions/revoke',
					'POST',
					user.pubkey,
					body
				);
				await authEvent?.sign();
				authHeaders.Authorization = `Nostr ${btoa(JSON.stringify(authEvent))}`;
			}
			// Otherwise backend will use HttpOnly cookie (sent automatically)

			await api.post(
				'/user/sessions/revoke',
				{ secret },
				{
					headers: authHeaders
				}
			);

			toast.success('Session revoked successfully');
			showRevokeModal = false;
			selectedSession = null;

			// Reload sessions
			await loadSessions();
		} catch (err) {
			error = `Failed to revoke session: ${err}`;
			toast.error('Failed to revoke session');
		}
	}

	function formatDate(dateStr: string): string {
		const date = new Date(dateStr);
		return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
	}

	// Load sessions when component mounts or when auth changes
	$effect(() => {
		loadSessions();
	});
</script>

<svelte:head>
	<title>Connected Apps - {BRAND.name}</title>
</svelte:head>

<div class="permissions-page">
	<div class="header">
		<div class="header-content">
			<div>
				<h1>Connected Apps</h1>
				<p class="subtitle">Manage apps that can sign events on your behalf via NIP-46</p>
			</div>
			<button class="btn-add-bunker" onclick={() => (showCreateModal = true)}>
				+ Add Bunker Connection
			</button>
		</div>
	</div>

	<CreateBunkerModal
		bind:show={showCreateModal}
		onClose={() => (showCreateModal = false)}
		onSuccess={() => {
			showCreateModal = false;
			loadSessions();
		}}
	/>

	{#if isLoading}
		<div class="loading">
			<div class="spinner"></div>
			<p>Loading sessions...</p>
		</div>
	{:else if error}
		<div class="error-box">
			<h3>Error</h3>
			<p>{error}</p>
			<button onclick={loadSessions}>Retry</button>
		</div>
	{:else if sessions.length === 0}
		<div class="empty-state">
			<h3>No Active Sessions</h3>
			<p>You haven't authorized any apps yet.</p>
		</div>
	{:else}
		<div class="permissions-list">
			{#each sessions as session}
				<div class="permission-card">
					<div class="card-header">
						<div>
							<h3>{session.application_name}</h3>
							{#if session.client_pubkey}
								<p class="policy-name">Client: {session.client_pubkey.substring(0, 16)}...</p>
							{/if}
						</div>
						<div class="card-actions">
							<button
								class="btn-revoke"
								onclick={() => {
									selectedSession = session;
									showRevokeModal = true;
								}}
							>
								Revoke
							</button>
						</div>
					</div>

					<div class="card-body">
						<div class="info-grid">
							<div class="info-item">
								<span class="label">Created:</span>
								<span class="value">{formatDate(session.created_at)}</span>
							</div>
							<div class="info-item">
								<span class="label">Last Activity:</span>
								<span class="value">
									{session.last_activity ? formatDate(session.last_activity) : 'Never'}
								</span>
							</div>
							<div class="info-item">
								<span class="label">Total Signs:</span>
								<span class="value">{session.activity_count}</span>
							</div>
							<div class="info-item">
								<span class="label">Bunker Pubkey:</span>
								<span class="value mono">{session.bunker_pubkey.substring(0, 16)}...</span>
							</div>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

{#if showRevokeModal && selectedSession}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="modal-overlay" onclick={() => (showRevokeModal = false)}>
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="modal" onclick={(e) => e.stopPropagation()}>
			<h3>Revoke Session?</h3>
			<p>
				Are you sure you want to revoke access for
				<strong>{selectedSession.application_name}</strong>?
			</p>
			<p class="warning">This app will no longer be able to sign events on your behalf.</p>
			<div class="modal-actions">
				<button class="btn-cancel" onclick={() => (showRevokeModal = false)}> Cancel </button>
				<button
					class="btn-confirm-revoke"
					onclick={() => selectedSession && revokeSession(selectedSession.secret)}
				>
					Revoke Access
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.permissions-page {
		max-width: 1200px;
		margin: 0 auto;
		padding: 2rem;
		min-height: 100vh;
		background: var(--color-divine-bg);
		color: var(--color-divine-text);
	}

	.header {
		margin-bottom: 2rem;
	}

	.header-content {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 2rem;
	}

	.header h1 {
		font-size: 1.75rem;
		margin: 0 0 0.25rem 0;
		color: var(--color-divine-text);
		font-weight: 600;
	}

	.subtitle {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		margin: 0;
	}

	.btn-add-bunker {
		padding: 0.5rem 1rem;
		background: var(--color-divine-green);
		color: #fff;
		border: 1px solid var(--color-divine-green);
		border-radius: var(--radius-md);
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		white-space: nowrap;
		transition: all 0.2s;
	}

	.btn-add-bunker:hover {
		background: var(--color-divine-green-dark);
		box-shadow: var(--shadow-sm);
	}

	.loading {
		text-align: center;
		padding: 4rem 2rem;
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid var(--color-divine-border);
		border-top: 3px solid var(--color-divine-green);
		border-radius: 50%;
		animation: spin 1s linear infinite;
		margin: 0 auto 1rem;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	.error-box {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		border-radius: var(--radius-md);
		padding: 2rem;
		text-align: center;
	}

	.error-box h3 {
		color: var(--color-divine-error);
		margin-top: 0;
	}

	.error-box button {
		margin-top: 1rem;
		padding: 0.5rem 1rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: var(--radius-md);
		cursor: pointer;
		font-size: 0.875rem;
	}

	.empty-state {
		text-align: center;
		padding: 4rem 2rem;
		color: var(--color-divine-text-secondary);
	}

	.permissions-list {
		display: grid;
		gap: 1rem;
	}

	.permission-card {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: var(--radius-md);
		overflow: hidden;
		transition: all 0.2s;
	}

	.permission-card:hover {
		border-color: var(--color-divine-green);
		box-shadow: var(--shadow-sm);
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 1rem 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
	}

	.card-header h3 {
		margin: 0 0 0.25rem 0;
		color: var(--color-divine-text);
		font-size: 1.1rem;
		font-weight: 600;
	}

	.policy-name {
		margin: 0;
		color: var(--color-divine-text-secondary);
		font-size: 0.8rem;
	}

	.card-actions {
		display: flex;
		gap: 0.75rem;
		align-items: center;
	}

	.btn-revoke {
		padding: 0.375rem 0.75rem;
		background: transparent;
		color: var(--color-divine-error);
		border: 1px solid var(--color-divine-error);
		border-radius: var(--radius-sm);
		cursor: pointer;
		font-size: 0.8rem;
		transition: all 0.2s;
	}

	.btn-revoke:hover {
		background: var(--color-divine-error);
		color: #fff;
	}

	.card-body {
		padding: 1rem 1.25rem;
	}

	.info-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
		gap: 0.75rem;
	}

	.info-item {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
	}

	.label {
		font-size: 0.7rem;
		color: var(--color-divine-text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.value {
		font-size: 0.875rem;
		color: var(--color-divine-text);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: 0.8rem;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.75);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
		backdrop-filter: blur(4px);
	}

	.modal {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: var(--radius-lg);
		padding: 1.5rem;
		max-width: 400px;
		width: 90%;
		box-shadow: var(--shadow-lg);
	}

	.modal h3 {
		margin-top: 0;
		margin-bottom: 0.75rem;
		color: var(--color-divine-text);
		font-size: 1.1rem;
	}

	.modal p {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		margin: 0.5rem 0;
	}

	.modal .warning {
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
		padding: 0.5rem 1rem;
		background: transparent;
		color: var(--color-divine-text-secondary);
		border: 1px solid var(--color-divine-border);
		border-radius: var(--radius-md);
		cursor: pointer;
		font-size: 0.875rem;
		transition: all 0.2s;
	}

	.btn-cancel:hover {
		background: var(--color-divine-border);
		color: var(--color-divine-text);
	}

	.btn-confirm-revoke {
		padding: 0.5rem 1rem;
		background: var(--color-divine-error);
		color: #fff;
		border: 1px solid var(--color-divine-error);
		border-radius: var(--radius-md);
		cursor: pointer;
		font-size: 0.875rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.btn-confirm-revoke:hover {
		background: #dc2626;
		border-color: #dc2626;
	}
</style>
