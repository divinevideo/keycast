<script lang="ts">
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { onMount } from 'svelte';

	const api = new KeycastApi();

	interface Policy {
		slug: string;
		display_name: string;
		description?: string;
	}

	interface Props {
		show: boolean;
		onClose: () => void;
		onSuccess: () => void;
	}

	let { show = $bindable(false), onClose, onSuccess }: Props = $props();

	let appName = $state('');
	let selectedPolicySlug = $state('full');
	let policies = $state<Policy[]>([]);
	let isCreating = $state(false);
	let bunkerUrl = $state('');
	let showCopySuccess = $state(false);

	onMount(async () => {
		try {
			// Public endpoint - no credentials needed
			const res = await api.get<{ policies: Policy[] }>('/policies', { credentials: 'omit' });
			policies = res.policies;
		} catch (err) {
			console.error('Failed to fetch policies:', err);
		}
	});

	async function handleCreate() {
		if (!appName.trim()) {
			toast.error('App name is required');
			return;
		}

		try {
			isCreating = true;

			const response = await api.post<{
				bunker_url: string;
				origin: string | null;
				app_name: string;
				bunker_pubkey: string;
				created_at: string;
			}>(
				'/user/bunker/create',
				{
					app_name: appName.trim(),
					policy_slug: selectedPolicySlug
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
		selectedPolicySlug = 'full';
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
				<h2>{bunkerUrl ? 'Connection Ready!' : 'Connect to Nostr App'}</h2>
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
						{showCopySuccess ? '✓ Copied!' : 'Copy Bunker URL'}
					</button>

					<div class="warning-box">
						<strong>Save this URL now!</strong>
						<p>This bunker URL acts like a password and is shown only once. Copy it now and paste it into your Nostr app. If you lose it, you can revoke this connection and create a new one.</p>
					</div>
				</div>
			{:else}
				<!-- Form state: Create bunker -->
				<div class="modal-body">
					<p class="description">
						Generate a connection URL to use your diVine Login with Nostr apps that support
						NIP-46 remote signing (Damus, Primal, Amethyst, etc).
					</p>

					<div class="form-group">
						<label for="appName">App Name</label>
						<input
							id="appName"
							type="text"
							bind:value={appName}
							placeholder="e.g. Primal, Damus, Amethyst"
							required
							disabled={isCreating}
						/>
						<p class="input-hint">Name of the app you're connecting to</p>
					</div>

					<div class="form-group">
						<label for="policy">Permissions</label>
						<select
							id="policy"
							bind:value={selectedPolicySlug}
							disabled={isCreating}
						>
							{#each policies as policy}
								<option value={policy.slug}>{policy.display_name}</option>
							{/each}
						</select>
						<p class="input-hint">What this connection is allowed to do with your identity</p>
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
		max-width: 480px;
		width: 90%;
		max-height: 90vh;
		overflow-y: auto;
		box-shadow: var(--shadow-lg);
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
	}

	.modal-header h2 {
		margin: 0;
		color: var(--color-divine-text);
		font-size: 1.25rem;
		font-weight: 600;
	}

	.close-btn {
		background: none;
		border: none;
		color: var(--color-divine-text-secondary);
		font-size: 1.5rem;
		cursor: pointer;
		padding: 0;
		width: 28px;
		height: 28px;
		line-height: 1;
		transition: color 0.2s;
	}

	.close-btn:hover {
		color: var(--color-divine-text);
	}

	.modal-body {
		padding: 1.25rem;
	}

	.description {
		color: var(--color-divine-text-secondary);
		margin-bottom: 1.25rem;
		font-size: 0.9rem;
		line-height: 1.5;
	}

	.form-group {
		margin-bottom: 1.25rem;
	}

	label {
		display: block;
		margin-bottom: 0.375rem;
		color: var(--color-divine-text);
		font-weight: 500;
		font-size: 0.875rem;
	}

	input {
		width: 100%;
		padding: 0.625rem 0.75rem;
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: var(--radius-md);
		color: var(--color-divine-text);
		font-size: 0.9rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
	}

	input:focus {
		outline: none;
		border-color: var(--color-divine-green);
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	select {
		width: 100%;
		padding: 0.625rem 0.75rem;
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: var(--radius-md);
		color: var(--color-divine-text);
		font-size: 0.9rem;
		box-sizing: border-box;
		transition: border-color 0.2s;
		cursor: pointer;
	}

	select:focus {
		outline: none;
		border-color: var(--color-divine-green);
	}

	select:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.input-hint {
		margin: 0.375rem 0 0 0;
		font-size: 0.75rem;
		color: var(--color-divine-text-secondary);
	}

	.modal-actions {
		display: flex;
		gap: 0.75rem;
		margin-top: 1.5rem;
	}

	.btn-cancel,
	.btn-create {
		flex: 1;
		padding: 0.625rem;
		border-radius: var(--radius-md);
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-cancel {
		background: transparent;
		color: var(--color-divine-text-secondary);
		border: 1px solid var(--color-divine-border);
	}

	.btn-cancel:hover:not(:disabled) {
		background: var(--color-divine-border);
		color: var(--color-divine-text);
	}

	.btn-create {
		background: var(--color-divine-green);
		color: #fff;
		border: 1px solid var(--color-divine-green);
	}

	.btn-create:hover:not(:disabled) {
		background: var(--color-divine-green-dark);
		box-shadow: var(--shadow-sm);
	}

	.btn-cancel:disabled,
	.btn-create:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.success-message {
		color: var(--color-divine-green);
		font-weight: 500;
		margin-bottom: 0.75rem;
		font-size: 0.9rem;
	}

	.bunker-url-display {
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: var(--radius-md);
		padding: 0.875rem;
		margin-bottom: 0.875rem;
		word-break: break-all;
	}

	.bunker-url-display code {
		color: var(--color-divine-green);
		font-size: 0.8rem;
		font-family: var(--font-mono);
	}

	.btn-copy {
		width: 100%;
		padding: 0.625rem;
		background: var(--color-divine-green);
		color: #fff;
		border: 1px solid var(--color-divine-green);
		border-radius: var(--radius-md);
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		margin-bottom: 0.875rem;
	}

	.btn-copy:hover {
		background: var(--color-divine-green-dark);
		box-shadow: var(--shadow-sm);
	}

	.help-text {
		color: #666;
		font-size: 0.875rem;
		line-height: 1.5;
	}

	.warning-box {
		background: rgba(245, 158, 11, 0.1);
		border: 1px solid rgba(245, 158, 11, 0.3);
		border-radius: 8px;
		padding: 1rem;
		margin-top: 0.5rem;
	}

	.warning-box strong {
		color: #f59e0b;
		display: block;
		margin-bottom: 0.5rem;
	}

	.warning-box p {
		color: #999;
		font-size: 0.875rem;
		line-height: 1.5;
		margin: 0;
	}
</style>
