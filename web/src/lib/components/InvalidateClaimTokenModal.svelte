<script lang="ts">
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';

	const api = new KeycastApi();

	interface Props {
		show: boolean;
		vineId: string;
		userDisplayName: string;
		onClose: () => void;
		onSuccess: () => void;
	}

	let {
		show = $bindable(false),
		vineId,
		userDisplayName,
		onClose,
		onSuccess
	}: Props = $props();

	let reason = $state('');
	let isInvalidating = $state(false);

	async function handleInvalidate() {
		try {
			isInvalidating = true;
			const body: { vine_id: string; reason?: string } = { vine_id: vineId };
			if (reason.trim()) body.reason = reason.trim();

			const res = await api.post<{
				invalidated_count: number;
				invalidated_at: string | null;
			}>('/admin/claim-tokens/invalidate', body);

			if (res.invalidated_count === 0) {
				toast.success('No active claim link to invalidate.');
			} else {
				toast.success('Claim link invalidated.');
			}
			reason = '';
			onSuccess();
			onClose();
		} catch (err: any) {
			toast.error(err?.message || 'Failed to invalidate claim link');
		} finally {
			isInvalidating = false;
		}
	}

	function handleCancel() {
		reason = '';
		onClose();
	}
</script>

{#if show}
	<div class="modal-overlay" role="dialog" aria-modal="true">
		<div class="modal-content">
			<h2>Invalidate claim link for {userDisplayName}?</h2>
			<p>
				This link will stop working immediately. The account stays unclaimed;
				you can issue a new link later with "Generate Claim Link" or
				"Regenerate."
			</p>

			<label for="invalidate-reason">Reason (optional)</label>
			<textarea
				id="invalidate-reason"
				bind:value={reason}
				rows="3"
				placeholder="e.g. credential suspected compromised; link sent to wrong person"
				disabled={isInvalidating}
			></textarea>

			<div class="modal-actions">
				<button class="btn-secondary" onclick={handleCancel} disabled={isInvalidating}>
					Cancel
				</button>
				<button
					class="btn-destructive"
					onclick={handleInvalidate}
					disabled={isInvalidating}
				>
					{isInvalidating ? 'Invalidating...' : 'Invalidate'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.modal-overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}
	.modal-content {
		background: #0f2e23;
		border: 1px solid #1c4033;
		border-radius: 12px;
		padding: 24px;
		max-width: 480px;
		width: 90%;
		color: #f9f7f6;
	}
	.modal-content h2 {
		margin: 0 0 12px 0;
		font-size: 18px;
	}
	.modal-content p {
		color: #beb3a7;
		font-size: 14px;
		line-height: 1.5;
		margin: 0 0 16px 0;
	}
	.modal-content label {
		display: block;
		font-size: 13px;
		color: #beb3a7;
		margin-bottom: 6px;
	}
	.modal-content textarea {
		width: 100%;
		background: #072218;
		border: 1px solid #1c4033;
		border-radius: 6px;
		color: #f9f7f6;
		padding: 8px 10px;
		font-size: 14px;
		font-family: inherit;
		resize: vertical;
		box-sizing: border-box;
	}
	.modal-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		margin-top: 20px;
	}
	.btn-secondary,
	.btn-destructive {
		padding: 8px 14px;
		border-radius: 6px;
		font-size: 14px;
		cursor: pointer;
		border: 1px solid transparent;
	}
	.btn-secondary {
		background: transparent;
		border-color: #1c4033;
		color: #beb3a7;
	}
	.btn-destructive {
		background: #7f1d1d;
		color: #fee2e2;
	}
	.btn-destructive:hover {
		background: #991b1b;
	}
	.btn-secondary:hover {
		background: #1c4033;
		color: #f9f7f6;
	}
</style>
