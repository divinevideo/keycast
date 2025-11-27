<script lang="ts">
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';

	const api = new KeycastApi();

	interface Props {
		show: boolean;
		onClose: () => void;
		onSuccess: () => void;
	}

	let { show = $bindable(false), onClose, onSuccess }: Props = $props();

	let appName = $state('');
	let relayUrl = $state('wss://relay.damus.io');
	let isCreating = $state(false);
	let bunkerUrl = $state('');
	let showCopySuccess = $state(false);

	async function handleCreate() {
		if (!appName.trim()) {
			toast.error('App name is required');
			return;
		}

		try {
			isCreating = true;

			const response = await api.post<{
				bunker_url: string;
				app_name: string;
				bunker_pubkey: string;
				created_at: string;
			}>(
				'/user/bunker/create',
				{
					app_name: appName,
					relay_url: relayUrl
				}
			);

			bunkerUrl = response.bunker_url;
			toast.success(`Bunker connection created for ${response.app_name}`);
		} catch (err: any) {
			console.error('Create bunker error:', err);
			toast.error(err.message || 'Failed to create bunker connection');
		} finally {
			isCreating = false;
		}
	}

	async function copyBunkerUrl() {
		try {
			await navigator.clipboard.writeText(bunkerUrl);
			showCopySuccess = true;
			setTimeout(() => (showCopySuccess = false), 2000);
			toast.success('Bunker URL copied!');
		} catch (err) {
			toast.error('Failed to copy');
		}
	}

	function handleClose() {
		if (bunkerUrl) {
			// Success - refresh parent and close
			onSuccess();
		}
		// Reset form
		appName = '';
		relayUrl = 'wss://relay.damus.io';
		bunkerUrl = '';
		showCopySuccess = false;
		onClose();
	}
</script>

{#if show}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="modal-overlay" onclick={handleClose}>
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="modal" onclick={(e) => e.stopPropagation()}>
			<div class="modal-header">
				<h2>{bunkerUrl ? 'Bunker Connection Created' : 'Create Bunker Connection'}</h2>
				<button class="close-btn" onclick={handleClose}>×</button>
			</div>

			{#if bunkerUrl}
				<!-- Success state: Show bunker URL -->
				<div class="modal-body">
					<p class="success-message">Copy this bunker URL to your NIP-46 client:</p>

					<div class="bunker-url-display">
						<code>{bunkerUrl}</code>
					</div>

					<button class="btn-copy" onclick={copyBunkerUrl}>
						{showCopySuccess ? '✓ Copied!' : '📋 Copy Bunker URL'}
					</button>

					<p class="help-text">
						This URL allows the app to request signatures via NIP-46. Paste it into your client
						application.
					</p>
				</div>
			{:else}
				<!-- Form state: Create bunker -->
				<div class="modal-body">
					<p class="description">
						Create a NIP-46 bunker connection for apps that don't support OAuth (manual
						copy/paste flow).
					</p>

					<div class="form-group">
						<label for="appName">App Name</label>
						<input
							id="appName"
							type="text"
							bind:value={appName}
							placeholder="My NIP-46 Client"
							required
							disabled={isCreating}
						/>
					</div>

					<div class="form-group">
						<label for="relayUrl">Relay URL</label>
						<input
							id="relayUrl"
							type="text"
							bind:value={relayUrl}
							placeholder="wss://relay.damus.io"
							disabled={isCreating}
						/>
					</div>

					<div class="modal-actions">
						<button class="btn-cancel" onclick={handleClose} disabled={isCreating}>
							Cancel
						</button>
						<button class="btn-create" onclick={handleCreate} disabled={isCreating}>
							{isCreating ? 'Creating...' : 'Create Connection'}
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}

<style>
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
		border: 1px solid #333;
		border-radius: 12px;
		max-width: 600px;
		width: 90%;
		max-height: 90vh;
		overflow-y: auto;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.5rem;
		border-bottom: 1px solid #333;
	}

	.modal-header h2 {
		margin: 0;
		color: #bb86fc;
		font-size: 1.5rem;
	}

	.close-btn {
		background: none;
		border: none;
		color: #999;
		font-size: 2rem;
		cursor: pointer;
		padding: 0;
		width: 32px;
		height: 32px;
		line-height: 1;
	}

	.close-btn:hover {
		color: #e0e0e0;
	}

	.modal-body {
		padding: 1.5rem;
	}

	.description {
		color: #999;
		margin-bottom: 1.5rem;
	}

	.form-group {
		margin-bottom: 1.5rem;
	}

	label {
		display: block;
		margin-bottom: 0.5rem;
		color: #e0e0e0;
		font-weight: 500;
	}

	input {
		width: 100%;
		padding: 0.75rem;
		background: #0a0a0a;
		border: 1px solid #444;
		border-radius: 6px;
		color: #e0e0e0;
		font-size: 1rem;
		box-sizing: border-box;
	}

	input:focus {
		outline: none;
		border-color: #bb86fc;
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.modal-actions {
		display: flex;
		gap: 1rem;
		margin-top: 2rem;
	}

	.btn-cancel,
	.btn-create {
		flex: 1;
		padding: 0.75rem;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-cancel {
		background: #2a2a2a;
		color: #e0e0e0;
	}

	.btn-cancel:hover:not(:disabled) {
		background: #3a3a3a;
	}

	.btn-create {
		background: #bb86fc;
		color: #000;
	}

	.btn-create:hover:not(:disabled) {
		background: #cb96fc;
	}

	.btn-cancel:disabled,
	.btn-create:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.success-message {
		color: #03dac6;
		font-weight: 500;
		margin-bottom: 1rem;
	}

	.bunker-url-display {
		background: #0a0a0a;
		border: 1px solid #444;
		border-radius: 6px;
		padding: 1rem;
		margin-bottom: 1rem;
		word-break: break-all;
	}

	.bunker-url-display code {
		color: #03dac6;
		font-size: 0.9rem;
		font-family: 'Courier New', monospace;
	}

	.btn-copy {
		width: 100%;
		padding: 0.75rem;
		background: #03dac6;
		color: #000;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.2s;
		margin-bottom: 1rem;
	}

	.btn-copy:hover {
		background: #13ebd6;
	}

	.help-text {
		color: #666;
		font-size: 0.875rem;
		line-height: 1.5;
	}
</style>
