<script lang="ts">
	import { getCurrentUser, setCurrentUser } from '$lib/current_user.svelte';
	import { getAccountStatus, isEmailVerified } from '$lib/account_status.svelte';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';
	import { toast } from 'svelte-hot-french-toast';
	import { goto } from '$app/navigation';

	const api = new KeycastApi();
	const currentUser = $derived(getCurrentUser());
	const user = $derived(currentUser?.user);
	const authMethod = $derived(currentUser?.authMethod);
	const accountStatus = $derived(getAccountStatus());
	const emailVerified = $derived(isEmailVerified());

	// Password verification state (shared)
	let mainPassword = $state('');
	let isVerifying = $state(false);
	let isPasswordVerified = $state(false);

	// Export Key Section
	let exportedNsec = $state('');
	let showExportedNsec = $state(false);
	let isExporting = $state(false);

	// Change Key Section
	let newNsec = $state('');
	let confirmText = $state('');
	let isChanging = $state(false);
	let showConfirmModal = $state(false);

	// Only allow cookie-based users (email/password) to use this page
	// Use untrack to prevent infinite loops during navigation
	$effect(() => {
		if (authMethod && authMethod !== 'cookie') {
			toast.error('This page is only for email/password users');
			goto('/', { replaceState: true });
		}
	});

	async function handleVerifyPassword() {
		if (!mainPassword) {
			toast.error('Please enter your password');
			return;
		}

		try {
			isVerifying = true;

			// Verify password
			await api.post('/user/verify-password', { password: mainPassword });

			isPasswordVerified = true;
			toast.success('Password verified - security settings unlocked');
		} catch (err: any) {
			console.error('Verify error:', err);
			toast.error(err.message || 'Invalid password');
		} finally {
			isVerifying = false;
		}
	}

	async function handleExportKey() {
		try {
			isExporting = true;

			// Get the nsec using the verified password
			const response = await api.post<{ key: string }>('/user/export-key-simple', {
				password: mainPassword,
				format: 'nsec'
			});

			exportedNsec = response.key;
			showExportedNsec = false; // Start hidden
			toast.success('Private key exported successfully');
		} catch (err: any) {
			console.error('Export error:', err);
			toast.error(err.message || 'Failed to export key');
		} finally {
			isExporting = false;
		}
	}

	function copyToClipboard() {
		if (!exportedNsec) return;

		navigator.clipboard.writeText(exportedNsec);
		toast.success('Copied to clipboard');
	}

	function openConfirmModal() {
		if (!newNsec) {
			toast.error('Please enter an nsec to import');
			return;
		}

		showConfirmModal = true;
	}

	async function handleChangeKey() {
		if (confirmText !== 'DELETE') {
			toast.error('Please type DELETE to confirm');
			return;
		}

		try {
			isChanging = true;

			const response = await api.post<{
				success: boolean;
				new_pubkey: string;
				message: string;
			}>('/user/change-key', {
				password: mainPassword,
				nsec: newNsec
			});

			toast.success(response.message);
			showConfirmModal = false;

			// Update current user with new pubkey and stay logged in
			setCurrentUser(response.new_pubkey, 'cookie');

			// Reset form
			newNsec = '';
			confirmText = '';

			// Optionally reload the page to refresh all data
			setTimeout(() => {
				window.location.href = '/';
			}, 2000);
		} catch (err: any) {
			console.error('Change key error:', err);
			toast.error(err.message || 'Failed to change key');
		} finally {
			isChanging = false;
		}
	}

	function handleLockSettings() {
		isPasswordVerified = false;
		mainPassword = '';
		exportedNsec = '';
	}
</script>

<svelte:head>
	<title>Security Settings - {BRAND.name}</title>
</svelte:head>

<div class="security-page">
	<div class="header">
		<h1>Security Settings</h1>
		<p class="subtitle">Manage your private key and account security</p>
	</div>

	{#if !emailVerified}
		<!-- Email Not Verified Message -->
		<div class="verification-required">
			<div class="verification-icon">
				<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
					<path d="M224,48H32a8,8,0,0,0-8,8V192a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A8,8,0,0,0,224,48ZM98.71,128,40,181.81V74.19Zm11.84,10.85,12,11.05a8,8,0,0,0,10.82,0l12-11.05,58,53.15H52.57ZM157.29,128,216,74.18V181.82Z"></path>
				</svg>
			</div>
			<h2>Email Verification Required</h2>
			<p>Please verify your email address to access security settings and export your private key.</p>
			{#if accountStatus?.email}
				<p class="email-hint">A verification email was sent to <strong>{accountStatus.email}</strong></p>
			{/if}
			<a href="/" class="btn-primary">Go to Dashboard</a>
		</div>
	{:else}
	<!-- Password Verification Section (Always Visible) -->
	<div class="section">
		<div class="section-header">
			<h2>🔐 Unlock Security Settings</h2>
			<p>Enter your password to access key management features</p>
		</div>

		<div class="form-container">
			{#if !isPasswordVerified}
				<div class="form-group">
					<label for="main-password">Password</label>
					<input
						id="main-password"
						type="password"
						bind:value={mainPassword}
						placeholder="Enter your password"
						disabled={isVerifying}
						onkeydown={(e) => e.key === 'Enter' && handleVerifyPassword()}
					/>
				</div>

				<button
					class="btn-primary"
					onclick={handleVerifyPassword}
					disabled={isVerifying || !mainPassword}
				>
					{isVerifying ? 'Verifying...' : 'Unlock Settings'}
				</button>
			{:else}
				<div class="verified-status">
					<span>✓ Password verified - settings unlocked</span>
					<button class="btn-secondary-small" onclick={handleLockSettings}>Lock</button>
				</div>
			{/if}
		</div>
	</div>

	{#if isPasswordVerified}
		<!-- Export Private Key Section -->
		<div class="section">
			<div class="section-header">
				<h2>🔑 Export Private Key</h2>
				<p>View and backup your Nostr private key (nsec)</p>
			</div>

			<div class="form-container">
				<button class="btn-primary" onclick={handleExportKey} disabled={isExporting}>
					{isExporting ? 'Exporting...' : 'Export Private Key'}
				</button>

				{#if exportedNsec}
					<div class="exported-key">
						<label>Your Private Key (nsec):</label>
						<div class="key-display">
							<input
								type={showExportedNsec ? 'text' : 'password'}
								value={exportedNsec}
								readonly
								class="nsec-input"
							/>
							<button class="btn-icon" onclick={() => (showExportedNsec = !showExportedNsec)}>
								{showExportedNsec ? '👁️' : '👁️‍🗨️'}
							</button>
						</div>
						<button class="btn-secondary" onclick={copyToClipboard}>📋 Copy to Clipboard</button>

						<div class="warning">
							⚠️ Never share this key. Anyone with this key controls your Nostr identity.
						</div>
					</div>
				{/if}
			</div>
		</div>

		<!-- Change Private Key Section -->
		<div class="section danger-section">
			<div class="section-header">
				<h2>🔄 Change Private Key</h2>
				<p>Replace your current Nostr private key with an existing one</p>
			</div>

			<div class="danger-warning">
				<strong>⚠️ DANGER ZONE</strong>
				<p>Changing your key will:</p>
				<ul>
					<li>Delete all connected apps (bunker connections)</li>
					<li>Give you a new Nostr public key (new identity)</li>
					<li>
						Your old identity stays in teams if you backed up the old nsec (sign with NIP-07 browser
						extension)
					</li>
				</ul>
			</div>

			<div class="form-container">
				<div class="form-group">
					<label for="new-nsec">New Private Key (nsec or hex)</label>
					<input
						id="new-nsec"
						type="text"
						bind:value={newNsec}
						placeholder="nsec1... or 64-char hex"
						disabled={isChanging}
					/>
					<small style="color: #999; font-size: 0.85rem;">
						Import an existing Nostr private key. You must provide your own key.
					</small>
				</div>

				<button class="btn-danger" onclick={openConfirmModal} disabled={isChanging || !newNsec}>
					Change Private Key
				</button>
			</div>
		</div>
	{/if}
	{/if}
</div>

<!-- Confirmation Modal -->
{#if showConfirmModal}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="modal-overlay" onclick={() => (showConfirmModal = false)}>
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="modal" onclick={(e) => e.stopPropagation()}>
			<h3>⚠️ Are you absolutely sure?</h3>
			<p>This will PERMANENTLY:</p>
			<ul>
				<li>Delete all connected apps</li>
				<li>Change your Nostr public key</li>
				<li>Cannot be undone</li>
			</ul>

			<div class="form-group">
				<label>Type "DELETE" to confirm:</label>
				<input type="text" bind:value={confirmText} placeholder="DELETE" autofocus />
			</div>

			<div class="modal-actions">
				<button class="btn-cancel" onclick={() => (showConfirmModal = false)}>Cancel</button>
				<button
					class="btn-confirm-danger"
					onclick={handleChangeKey}
					disabled={isChanging || confirmText !== 'DELETE'}
				>
					{isChanging ? 'Changing...' : 'Yes, Change My Key'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.security-page {
		max-width: 800px;
		margin: 0 auto;
		padding: 2rem;
		min-height: 100vh;
		background: #0a0a0a;
		color: #e0e0e0;
	}

	.header {
		margin-bottom: 3rem;
	}

	.header h1 {
		font-size: 2.5rem;
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-purple);
	}

	.subtitle {
		color: #999;
		font-size: 1.1rem;
		margin: 0;
	}

	.verification-required {
		background: #1a1a1a;
		border: 1px solid rgba(251, 191, 36, 0.3);
		border-radius: 12px;
		padding: 3rem 2rem;
		text-align: center;
	}

	.verification-icon {
		color: rgb(251 191 36);
		margin-bottom: 1.5rem;
	}

	.verification-required h2 {
		color: #e0e0e0;
		margin: 0 0 1rem 0;
		font-size: 1.5rem;
	}

	.verification-required p {
		color: #999;
		margin: 0 0 1rem 0;
		max-width: 500px;
		margin-left: auto;
		margin-right: auto;
	}

	.verification-required .email-hint {
		font-size: 0.9rem;
		margin-bottom: 1.5rem;
	}

	.verification-required .email-hint strong {
		color: #e0e0e0;
	}

	.verification-required .btn-primary {
		display: inline-block;
	}

	.section {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		padding: 2rem;
		margin-bottom: 2rem;
	}

	.danger-section {
		border-color: #f44336;
	}

	.section-header h2 {
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-purple);
		font-size: 1.5rem;
	}

	.section-header p {
		color: #999;
		margin: 0 0 1.5rem 0;
	}

	.danger-warning {
		background: #3a1f1f;
		border: 2px solid #f44336;
		border-radius: 8px;
		padding: 1.5rem;
		margin-bottom: 1.5rem;
	}

	.danger-warning strong {
		color: #f44336;
		display: block;
		margin-bottom: 0.5rem;
	}

	.danger-warning ul {
		margin: 0.5rem 0 0 1.5rem;
		color: #e0e0e0;
	}

	.form-container {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	label {
		color: #e0e0e0;
		font-size: 0.9rem;
		font-weight: 500;
	}

	input[type='text'],
	input[type='password'] {
		padding: 0.75rem;
		background: #0a0a0a;
		border: 1px solid #444;
		border-radius: 6px;
		color: #e0e0e0;
		font-size: 1rem;
	}

	input:focus {
		outline: none;
		border-color: var(--color-divine-purple);
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.verified-status {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1rem;
		background: #1f3a1f;
		border: 1px solid #4caf50;
		border-radius: 6px;
		color: #4caf50;
	}

	.btn-primary,
	.btn-secondary,
	.btn-secondary-small,
	.btn-danger {
		padding: 0.75rem 1.5rem;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.2s;
	}

	.btn-secondary-small {
		padding: 0.5rem 1rem;
		font-size: 0.9rem;
	}

	.btn-primary {
		background: var(--color-divine-green);
		color: #fff;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--color-divine-green-dark);
	}

	.btn-secondary,
	.btn-secondary-small {
		background: #333;
		color: #e0e0e0;
	}

	.btn-secondary:hover:not(:disabled),
	.btn-secondary-small:hover:not(:disabled) {
		background: #444;
	}

	.btn-danger {
		background: #f44336;
		color: #fff;
	}

	.btn-danger:hover:not(:disabled) {
		background: #d32f2f;
	}

	button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.exported-key {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		padding: 1.5rem;
		background: #0a0a0a;
		border: 1px solid #444;
		border-radius: 8px;
		margin-top: 1rem;
	}

	.key-display {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.nsec-input {
		flex: 1;
		font-family: monospace;
	}

	.btn-icon {
		padding: 0.75rem;
		background: #333;
		border: 1px solid #444;
		border-radius: 6px;
		cursor: pointer;
		font-size: 1.2rem;
	}

	.btn-icon:hover {
		background: #444;
	}

	.warning {
		color: #f44336;
		font-weight: bold;
		padding: 1rem;
		background: #3a1f1f;
		border-radius: 6px;
		text-align: center;
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
		border: 2px solid #f44336;
		border-radius: 12px;
		padding: 2rem;
		max-width: 500px;
		width: 90%;
	}

	.modal h3 {
		margin-top: 0;
		color: #f44336;
	}

	.modal ul {
		margin: 1rem 0 1rem 1.5rem;
		color: #e0e0e0;
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
		border-radius: 6px;
		cursor: pointer;
		font-size: 1rem;
	}

	.btn-confirm-danger {
		padding: 0.75rem 1.5rem;
		background: #f44336;
		color: #fff;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		font-size: 1rem;
		font-weight: bold;
	}

	.btn-confirm-danger:hover:not(:disabled) {
		background: #d32f2f;
	}

	.btn-confirm-danger:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
