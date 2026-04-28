<script lang="ts">
	import { onMount } from 'svelte';
	import { BRAND } from '$lib/brand';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import {
		ArrowLeft,
		Plus,
		Trash,
		PencilSimple,
		FloppyDisk,
		X,
		Check,
		XCircle,
		CheckCircle,
		Warning,
		ShieldCheck
	} from 'phosphor-svelte';

	const api = new KeycastApi();

	interface RegisteredClient {
		id: number;
		client_id: string;
		name: string;
		allowed_redirect_uris: string[];
		created_at: string;
		updated_at: string;
	}

	let status = $state<'loading' | 'not-admin' | 'ready'>('loading');

	let clients = $state<RegisteredClient[]>([]);
	let isLoadingClients = $state(false);
	let listError = $state<string | null>(null);

	// New client form
	let newClientId = $state('');
	let newClientName = $state('');
	let newRedirectUris = $state<string[]>(['']);
	let isCreating = $state(false);

	// Edit state — keyed by row id
	let editingId = $state<number | null>(null);
	let editName = $state('');
	let editUris = $state<string[]>([]);
	let isSaving = $state(false);

	// Delete confirm modal
	let deleteCandidate = $state<RegisteredClient | null>(null);
	let isDeleting = $state(false);

	// Inline pattern tester
	let testPattern = $state('');
	let testUri = $state('');
	let testResult = $state<null | { matches: boolean; pattern: string; uri: string }>(null);
	let isTesting = $state(false);

	onMount(async () => {
		try {
			const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
			if (!response.is_admin || response.role !== 'full') {
				status = 'not-admin';
				return;
			}
		} catch {
			goto('/login?redirect=/admin/registered-clients', { replaceState: true });
			return;
		}

		status = 'ready';
		await loadClients();
	});

	async function loadClients() {
		isLoadingClients = true;
		listError = null;
		try {
			const result = await api.get<{ clients: RegisteredClient[] }>('/admin/registered-clients');
			clients = result.clients;
		} catch (err: any) {
			listError = err?.message || 'Failed to load registered clients';
		} finally {
			isLoadingClients = false;
		}
	}

	function addNewUriRow() {
		newRedirectUris = [...newRedirectUris, ''];
	}

	function removeNewUriRow(i: number) {
		newRedirectUris = newRedirectUris.filter((_, idx) => idx !== i);
		if (newRedirectUris.length === 0) newRedirectUris = [''];
	}

	function resetNewForm() {
		newClientId = '';
		newClientName = '';
		newRedirectUris = [''];
	}

	async function createClient() {
		const cid = newClientId.trim();
		const name = newClientName.trim();
		const uris = newRedirectUris.map((u) => u.trim()).filter((u) => u.length > 0);

		if (!cid) {
			toast.error('client_id is required');
			return;
		}
		if (!name) {
			toast.error('name is required');
			return;
		}
		if (uris.length === 0) {
			toast.error('At least one redirect URI is required');
			return;
		}

		isCreating = true;
		try {
			await api.post<RegisteredClient>('/admin/registered-clients', {
				client_id: cid,
				name,
				allowed_redirect_uris: uris
			});
			toast.success(`Created client "${cid}"`);
			resetNewForm();
			await loadClients();
		} catch (err: any) {
			toast.error(err?.message || 'Failed to create client');
		} finally {
			isCreating = false;
		}
	}

	function startEdit(c: RegisteredClient) {
		editingId = c.id;
		editName = c.name;
		editUris = [...c.allowed_redirect_uris];
		if (editUris.length === 0) editUris = [''];
	}

	function cancelEdit() {
		editingId = null;
		editName = '';
		editUris = [];
	}

	function addEditUriRow() {
		editUris = [...editUris, ''];
	}

	function removeEditUriRow(i: number) {
		editUris = editUris.filter((_, idx) => idx !== i);
		if (editUris.length === 0) editUris = [''];
	}

	async function saveEdit(c: RegisteredClient) {
		const name = editName.trim();
		const uris = editUris.map((u) => u.trim()).filter((u) => u.length > 0);
		if (!name) {
			toast.error('name is required');
			return;
		}
		if (uris.length === 0) {
			toast.error('At least one redirect URI is required');
			return;
		}

		isSaving = true;
		try {
			await api.patch<RegisteredClient>(`/admin/registered-clients/${c.id}`, {
				name,
				allowed_redirect_uris: uris
			});
			toast.success(`Updated "${c.client_id}"`);
			cancelEdit();
			await loadClients();
		} catch (err: any) {
			toast.error(err?.message || 'Failed to update client');
		} finally {
			isSaving = false;
		}
	}

	function openDelete(c: RegisteredClient) {
		deleteCandidate = c;
	}

	function closeDelete() {
		deleteCandidate = null;
	}

	async function confirmDelete() {
		if (!deleteCandidate) return;
		isDeleting = true;
		try {
			await api.delete<{ deleted: boolean }>(
				`/admin/registered-clients/${deleteCandidate.id}`
			);
			toast.success(`Deleted "${deleteCandidate.client_id}"`);
			deleteCandidate = null;
			await loadClients();
		} catch (err: any) {
			toast.error(err?.message || 'Failed to delete client');
		} finally {
			isDeleting = false;
		}
	}

	async function runPatternTest() {
		const pattern = testPattern.trim();
		const uri = testUri.trim();
		if (!pattern || !uri) {
			toast.error('Both pattern and URI are required');
			return;
		}
		isTesting = true;
		try {
			const result = await api.post<{ matches: boolean }>(
				'/admin/registered-clients/test',
				{ pattern, uri }
			);
			testResult = { matches: result.matches, pattern, uri };
		} catch (err: any) {
			toast.error(err?.message || 'Test failed');
		} finally {
			isTesting = false;
		}
	}

	function formatDate(iso: string): string {
		return new Date(iso).toLocaleString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	}
</script>

<svelte:head>
	<title>Registered OAuth Clients - {BRAND.name}</title>
</svelte:head>

{#if status === 'loading'}
	<div class="page">
		<div class="loading">Loading...</div>
	</div>
{:else if status === 'not-admin'}
	<div class="page">
		<div class="access-denied">
			<Warning size={48} weight="fill" />
			<h2>Access Denied</h2>
			<p>Full admin access is required to manage registered OAuth clients.</p>
		</div>
	</div>
{:else}
	<div class="page">
		<div class="header">
			<a href="/admin" class="back-link">
				<ArrowLeft size={16} />
				Back to Admin
			</a>
			<h1>Registered OAuth Clients</h1>
			<p class="subtitle">
				Manage the OAuth client allowlist for this tenant. Registered clients restrict which
				redirect URIs are accepted; unregistered clients accept any HTTPS redirect.
			</p>
		</div>

		<!-- Add new client -->
		<div class="section">
			<div class="section-header">
				<div class="section-icon"><Plus size={24} weight="duotone" /></div>
				<div>
					<h2>Add a registered client</h2>
					<p>Define a new OAuth client and the redirect URI patterns it may use.</p>
				</div>
			</div>

			<form
				class="add-form"
				onsubmit={(e) => {
					e.preventDefault();
					createClient();
				}}
			>
				<div class="form-row">
					<label>
						<span class="label">client_id</span>
						<input
							type="text"
							bind:value={newClientId}
							placeholder="my-app"
							disabled={isCreating}
						/>
					</label>
					<label>
						<span class="label">Display name</span>
						<input
							type="text"
							bind:value={newClientName}
							placeholder="My App"
							disabled={isCreating}
						/>
					</label>
				</div>

				<div class="uri-list">
					<span class="label">Allowed redirect URI patterns</span>
					{#each newRedirectUris as _uri, i}
						<div class="uri-row">
							<input
								type="text"
								bind:value={newRedirectUris[i]}
								placeholder="https://app.example.com/cb"
								disabled={isCreating}
							/>
							<button
								type="button"
								class="btn-icon-sm"
								onclick={() => removeNewUriRow(i)}
								title="Remove"
								disabled={isCreating}
							>
								<X size={14} />
							</button>
						</div>
					{/each}
					<button
						type="button"
						class="btn-link"
						onclick={addNewUriRow}
						disabled={isCreating}
					>
						<Plus size={14} /> Add another URI
					</button>
					<p class="hint">
						Wildcard <code>*</code> matches a single path segment (no <code>/</code>). Examples: <code>https://*.example.com/cb</code>, <code>http://localhost:*/cb</code>.
					</p>
				</div>

				<button type="submit" class="btn-primary" disabled={isCreating}>
					{isCreating ? 'Creating...' : 'Create client'}
				</button>
			</form>
		</div>

		<!-- Pattern tester -->
		<div class="section">
			<div class="section-header">
				<div class="section-icon"><ShieldCheck size={24} weight="duotone" /></div>
				<div>
					<h2>Test a redirect URI</h2>
					<p>Verify whether a candidate URI matches a pattern (uses the same matcher as OAuth).</p>
				</div>
			</div>

			<form
				class="test-form"
				onsubmit={(e) => {
					e.preventDefault();
					runPatternTest();
				}}
			>
				<label>
					<span class="label">Pattern</span>
					<input
						type="text"
						bind:value={testPattern}
						placeholder="https://*.example.com/cb"
						disabled={isTesting}
					/>
				</label>
				<label>
					<span class="label">URI</span>
					<input
						type="text"
						bind:value={testUri}
						placeholder="https://staging.example.com/cb"
						disabled={isTesting}
					/>
				</label>
				<button type="submit" class="btn-primary" disabled={isTesting}>
					{isTesting ? 'Testing...' : 'Test match'}
				</button>
			</form>

			{#if testResult}
				<div class="test-result {testResult.matches ? 'match' : 'nomatch'}">
					{#if testResult.matches}
						<CheckCircle size={20} weight="fill" />
						<span>Matches: <code>{testResult.uri}</code> would be accepted by pattern <code>{testResult.pattern}</code>.</span>
					{:else}
						<XCircle size={20} weight="fill" />
						<span>No match: <code>{testResult.uri}</code> would be rejected by pattern <code>{testResult.pattern}</code>.</span>
					{/if}
				</div>
			{/if}
		</div>

		<!-- List -->
		<div class="section">
			<div class="section-header">
				<div class="section-icon"><ShieldCheck size={24} weight="duotone" /></div>
				<div>
					<h2>Registered clients ({clients.length})</h2>
					<p>Edit or delete existing entries. Deleting an entry breaks that client's OAuth flow immediately.</p>
				</div>
			</div>

			{#if listError}
				<div class="list-error">
					<Warning size={16} />
					<span>{listError}</span>
				</div>
			{/if}

			{#if isLoadingClients}
				<p class="loading-text">Loading...</p>
			{:else if clients.length === 0}
				<p class="empty-text">No registered clients yet.</p>
			{:else}
				<table class="clients-table">
					<thead>
						<tr>
							<th>client_id</th>
							<th>Name</th>
							<th>Allowed redirect URIs</th>
							<th>Created</th>
							<th>Updated</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{#each clients as c}
							<tr>
								<td><code>{c.client_id}</code></td>
								<td>
									{#if editingId === c.id}
										<input type="text" bind:value={editName} disabled={isSaving} />
									{:else}
										{c.name}
									{/if}
								</td>
								<td class="uris-cell">
									{#if editingId === c.id}
										{#each editUris as _u, i}
											<div class="uri-row">
												<input
													type="text"
													bind:value={editUris[i]}
													disabled={isSaving}
												/>
												<button
													type="button"
													class="btn-icon-sm"
													onclick={() => removeEditUriRow(i)}
													title="Remove"
													disabled={isSaving}
												>
													<X size={14} />
												</button>
											</div>
										{/each}
										<button
											type="button"
											class="btn-link"
											onclick={addEditUriRow}
											disabled={isSaving}
										>
											<Plus size={14} /> Add URI
										</button>
									{:else}
										<ul class="uri-list-display">
											{#each c.allowed_redirect_uris as uri}
												<li><code>{uri}</code></li>
											{/each}
										</ul>
									{/if}
								</td>
								<td class="date-cell">{formatDate(c.created_at)}</td>
								<td class="date-cell">{formatDate(c.updated_at)}</td>
								<td class="actions-cell">
									{#if editingId === c.id}
										<button
											class="btn-icon"
											onclick={() => saveEdit(c)}
											disabled={isSaving}
											title="Save"
										>
											<FloppyDisk size={18} />
										</button>
										<button
											class="btn-icon"
											onclick={cancelEdit}
											disabled={isSaving}
											title="Cancel"
										>
											<X size={18} />
										</button>
									{:else}
										<button
											class="btn-icon"
											onclick={() => startEdit(c)}
											title="Edit"
										>
											<PencilSimple size={18} />
										</button>
										<button
											class="btn-icon danger"
											onclick={() => openDelete(c)}
											title="Delete"
										>
											<Trash size={18} />
										</button>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>
	</div>
{/if}

<!-- Delete confirm modal -->
{#if deleteCandidate}
	<div
		class="modal-backdrop"
		role="presentation"
		onclick={(e) => {
			if (e.target === e.currentTarget) closeDelete();
		}}
	>
		<div class="modal" role="dialog" aria-modal="true">
			<h3>Delete <code>{deleteCandidate.client_id}</code>?</h3>
			<p class="warning-text">
				<Warning size={16} weight="fill" />
				This will immediately break OAuth for any live integration using this client_id. There is no undo.
			</p>
			<div class="modal-actions">
				<button class="btn-secondary" onclick={closeDelete} disabled={isDeleting}>Cancel</button>
				<button class="btn-danger" onclick={confirmDelete} disabled={isDeleting}>
					{isDeleting ? 'Deleting...' : 'Delete client'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.page {
		max-width: 1100px;
		margin: 0 auto;
		padding: 2rem 1.5rem;
		color: var(--color-text, #f1f5f9);
	}

	.loading,
	.access-denied {
		text-align: center;
		padding: 4rem 2rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.access-denied h2 {
		margin: 1rem 0 0.5rem;
	}

	.header {
		margin-bottom: 2rem;
	}

	.back-link {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		font-size: 0.85rem;
		color: var(--color-text-muted, #94a3b8);
		text-decoration: none;
		margin-bottom: 0.75rem;
	}

	.back-link:hover {
		color: var(--color-text, #f1f5f9);
	}

	.header h1 {
		font-size: 1.75rem;
		margin: 0;
	}

	.subtitle {
		color: var(--color-text-muted, #94a3b8);
		margin: 0.4rem 0 0;
	}

	.section {
		background: var(--color-surface, rgba(15, 23, 42, 0.6));
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.18));
		border-radius: 0.75rem;
		padding: 1.5rem;
		margin-bottom: 1.5rem;
	}

	.section-header {
		display: flex;
		gap: 0.85rem;
		align-items: flex-start;
		margin-bottom: 1.25rem;
	}

	.section-icon {
		flex-shrink: 0;
		color: var(--color-accent, #8b5cf6);
	}

	.section-header h2 {
		margin: 0;
		font-size: 1.15rem;
	}

	.section-header p {
		margin: 0.25rem 0 0;
		font-size: 0.85rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.add-form,
	.test-form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 1rem;
	}

	@media (max-width: 640px) {
		.form-row {
			grid-template-columns: 1fr;
		}
	}

	.label {
		display: block;
		font-size: 0.78rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted, #94a3b8);
		margin-bottom: 0.35rem;
	}

	input[type='text'] {
		width: 100%;
		padding: 0.55rem 0.75rem;
		background: var(--color-input-bg, rgba(15, 23, 42, 0.9));
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.25));
		border-radius: 0.4rem;
		color: var(--color-text, #f1f5f9);
		font-size: 0.95rem;
		font-family: inherit;
	}

	input[type='text']:focus {
		outline: none;
		border-color: var(--color-accent, #8b5cf6);
	}

	input[type='text']:disabled {
		opacity: 0.6;
	}

	.uri-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.uri-row {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.uri-row input {
		flex: 1;
	}

	.hint {
		font-size: 0.8rem;
		color: var(--color-text-muted, #94a3b8);
		margin: 0.25rem 0 0;
	}

	.hint code,
	.uri-list-display code,
	.clients-table code {
		font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
		font-size: 0.85em;
		background: rgba(148, 163, 184, 0.15);
		padding: 0.1rem 0.35rem;
		border-radius: 0.25rem;
	}

	.btn-primary {
		align-self: flex-start;
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.55rem 1rem;
		background: var(--color-accent, #8b5cf6);
		color: white;
		border: none;
		border-radius: 0.4rem;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: pointer;
	}

	.btn-primary:hover:not(:disabled) {
		opacity: 0.9;
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-secondary,
	.btn-danger {
		padding: 0.5rem 0.9rem;
		border-radius: 0.4rem;
		font-size: 0.9rem;
		font-weight: 600;
		cursor: pointer;
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.25));
	}

	.btn-secondary {
		background: transparent;
		color: var(--color-text, #f1f5f9);
	}

	.btn-danger {
		background: #b91c1c;
		color: white;
		border-color: #b91c1c;
	}

	.btn-danger:disabled,
	.btn-secondary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-link {
		align-self: flex-start;
		background: none;
		border: none;
		color: var(--color-accent, #8b5cf6);
		font-size: 0.85rem;
		cursor: pointer;
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.25rem 0;
	}

	.btn-link:hover:not(:disabled) {
		text-decoration: underline;
	}

	.btn-icon {
		background: transparent;
		border: none;
		color: var(--color-text-muted, #94a3b8);
		cursor: pointer;
		padding: 0.4rem;
		border-radius: 0.3rem;
	}

	.btn-icon:hover {
		color: var(--color-text, #f1f5f9);
		background: rgba(148, 163, 184, 0.12);
	}

	.btn-icon.danger:hover {
		color: #fca5a5;
	}

	.btn-icon-sm {
		background: transparent;
		border: none;
		color: var(--color-text-muted, #94a3b8);
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 0.25rem;
	}

	.btn-icon-sm:hover {
		background: rgba(148, 163, 184, 0.18);
		color: var(--color-text, #f1f5f9);
	}

	.test-result {
		margin-top: 1rem;
		padding: 0.85rem 1rem;
		border-radius: 0.45rem;
		display: flex;
		gap: 0.6rem;
		align-items: center;
		font-size: 0.9rem;
	}

	.test-result.match {
		background: rgba(34, 197, 94, 0.12);
		color: #86efac;
		border: 1px solid rgba(34, 197, 94, 0.3);
	}

	.test-result.nomatch {
		background: rgba(239, 68, 68, 0.12);
		color: #fca5a5;
		border: 1px solid rgba(239, 68, 68, 0.3);
	}

	.list-error {
		display: flex;
		gap: 0.4rem;
		align-items: center;
		color: #fca5a5;
		font-size: 0.9rem;
		margin-bottom: 0.75rem;
	}

	.loading-text,
	.empty-text {
		color: var(--color-text-muted, #94a3b8);
		font-style: italic;
		margin: 0;
	}

	.clients-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 0.9rem;
	}

	.clients-table th,
	.clients-table td {
		padding: 0.65rem 0.75rem;
		border-bottom: 1px solid var(--color-border, rgba(148, 163, 184, 0.15));
		text-align: left;
		vertical-align: top;
	}

	.clients-table th {
		font-size: 0.78rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted, #94a3b8);
		font-weight: 600;
	}

	.uris-cell {
		min-width: 280px;
	}

	.uri-list-display {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.date-cell {
		white-space: nowrap;
		font-size: 0.82rem;
		color: var(--color-text-muted, #94a3b8);
	}

	.actions-cell {
		white-space: nowrap;
		text-align: right;
	}

	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.55);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
	}

	.modal {
		background: var(--color-surface, #1e293b);
		border: 1px solid var(--color-border, rgba(148, 163, 184, 0.25));
		border-radius: 0.6rem;
		padding: 1.5rem;
		max-width: 480px;
		width: 90%;
	}

	.modal h3 {
		margin: 0 0 0.75rem;
	}

	.warning-text {
		display: flex;
		gap: 0.5rem;
		align-items: flex-start;
		color: #fca5a5;
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid rgba(239, 68, 68, 0.3);
		padding: 0.65rem 0.8rem;
		border-radius: 0.4rem;
		margin: 0 0 1rem;
		font-size: 0.88rem;
	}

	.modal-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.6rem;
	}
</style>
