<script lang="ts">
	import { getCurrentUser } from '$lib/current_user.svelte';
	import { KeycastApi } from '$lib/keycast_api.svelte';
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
	<title>Connected Apps - Keycast</title>
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
		background: #0a0a0a;
		color: #e0e0e0;
	}

	.header {
		margin-bottom: 3rem;
	}

	.header-content {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: 2rem;
	}

	.header h1 {
		font-size: 2.5rem;
		margin: 0 0 0.5rem 0;
		color: #bb86fc;
	}

	.subtitle {
		color: #999;
		font-size: 1.1rem;
		margin: 0;
	}

	.btn-add-bunker {
		padding: 0.75rem 1.5rem;
		background: #bb86fc;
		color: #000;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		white-space: nowrap;
		transition: background 0.2s;
	}

	.btn-add-bunker:hover {
		background: #cb96fc;
	}

	.loading {
		text-align: center;
		padding: 4rem 2rem;
	}

	.spinner {
		width: 50px;
		height: 50px;
		border: 4px solid #333;
		border-top: 4px solid #bb86fc;
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
		background: #3a1f1f;
		border: 2px solid #f44336;
		border-radius: 8px;
		padding: 2rem;
		text-align: center;
	}

	.error-box h3 {
		color: #f44336;
		margin-top: 0;
	}

	.error-box button {
		margin-top: 1rem;
		padding: 0.5rem 1.5rem;
		background: #bb86fc;
		color: #000;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 1rem;
	}

	.empty-state {
		text-align: center;
		padding: 4rem 2rem;
		color: #999;
	}

	.permissions-list {
		display: grid;
		gap: 1.5rem;
	}

	.permission-card {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		overflow: hidden;
		transition: border-color 0.2s;
	}

	.permission-card:hover {
		border-color: #bb86fc;
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 1.5rem;
		border-bottom: 1px solid #333;
	}

	.card-header h3 {
		margin: 0 0 0.5rem 0;
		color: #bb86fc;
		font-size: 1.5rem;
	}

	.policy-name {
		margin: 0;
		color: #999;
		font-size: 0.9rem;
	}

	.card-actions {
		display: flex;
		gap: 1rem;
		align-items: center;
	}

	.btn-revoke {
		padding: 0.5rem 1rem;
		background: transparent;
		color: #f44336;
		border: 1px solid #f44336;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.9rem;
		transition: all 0.2s;
	}

	.btn-revoke:hover {
		background: #f44336;
		color: #fff;
	}

	.card-body {
		padding: 1.5rem;
	}

	.info-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 1rem;
	}

	.info-item {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.label {
		font-size: 0.85rem;
		color: #999;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.value {
		font-size: 1rem;
		color: #e0e0e0;
	}

	.mono {
		font-family: monospace;
	}

	.modal-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: rgba(0, 0, 0, 0.8);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.modal {
		background: #1a1a1a;
		border: 1px solid #444;
		border-radius: 12px;
		padding: 2rem;
		max-width: 500px;
		width: 90%;
	}

	.modal h3 {
		margin-top: 0;
		color: #bb86fc;
	}

	.modal .warning {
		color: #f44336;
		font-weight: bold;
	}

	.modal-actions {
		display: flex;
		gap: 1rem;
		margin-top: 2rem;
		justify-content: flex-end;
	}

	.btn-cancel {
		padding: 0.75rem 1.5rem;
		background: #333;
		color: #e0e0e0;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 1rem;
	}

	.btn-confirm-revoke {
		padding: 0.75rem 1.5rem;
		background: #f44336;
		color: #fff;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 1rem;
		font-weight: bold;
	}

	.btn-confirm-revoke:hover {
		background: #d32f2f;
	}
</style>
