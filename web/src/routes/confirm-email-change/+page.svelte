<script lang="ts">
	import { page } from '$app/stores';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';

	const api = new KeycastApi();

	const token = $derived($page.url.searchParams.get('token'));

	let status = $state<'idle' | 'loading' | 'done' | 'error'>('idle');
	let message = $state('');

	// Auto-submit once on mount when a token is present.
	let submitted = $state(false);
	$effect(() => {
		if (token && !submitted) {
			submitted = true;
			confirm();
		}
	});

	async function confirm() {
		if (!token) return;
		try {
			status = 'loading';
			const res = await api.post<{ success: boolean; message: string }>(
				'/auth/confirm-email-change',
				{ token }
			);
			status = 'done';
			message = res.message || 'Email change confirmed.';
		} catch (err: any) {
			status = 'error';
			message = err.message || 'This confirmation link is invalid or has expired.';
		}
	}
</script>

<svelte:head>
	<title>Confirm Email Change - {BRAND.name}</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<a href="/" class="auth-branding">
			<img src="/divine-logo.svg" alt={BRAND.shortName} class="auth-logo-img" />
			<span class="auth-logo-sub">Login</span>
		</a>

		<h1>Confirm Email Change</h1>

		{#if !token}
			<div class="error-message">
				<p>Invalid or missing confirmation token.</p>
				<p>Please use the link from your email.</p>
			</div>
		{:else if status === 'loading' || status === 'idle'}
			<p class="subtitle">Confirming...</p>
		{:else if status === 'done'}
			<p class="subtitle">{message}</p>
		{:else}
			<div class="error-message">
				<p>{message}</p>
			</div>
		{/if}

		<p class="auth-link">
			<a href="/settings/security">Back to Settings</a>
		</p>
	</div>
</div>

<style>
	.auth-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 1rem;
		background: var(--color-divine-bg);
	}

	.auth-container {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 1rem;
		padding: 2rem;
		max-width: 420px;
		width: 100%;
		box-shadow: 0 2px 8px rgba(39, 197, 139, 0.08);
	}

	.auth-branding {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 2px;
		text-decoration: none;
		margin-bottom: 1.5rem;
	}

	.auth-branding:hover {
		opacity: 0.85;
	}

	.auth-logo-img {
		height: 28px;
	}

	.auth-logo-sub {
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 11px;
		letter-spacing: 3px;
		text-transform: uppercase;
		color: var(--color-divine-green);
		opacity: 0.6;
	}

	h1 {
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-text);
		font-family: var(--font-heading);
		font-size: 1.75rem;
		font-weight: 700;
		text-align: center;
		letter-spacing: -0.02em;
	}

	.subtitle {
		color: var(--color-divine-text-secondary);
		margin: 0 0 1.5rem 0;
		text-align: center;
		font-size: 0.95rem;
	}

	.auth-link {
		text-align: center;
		margin-top: 1rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.875rem;
	}

	.auth-link a {
		color: var(--color-divine-green);
		text-decoration: none;
		font-weight: 500;
	}

	.auth-link a:hover {
		text-decoration: underline;
	}

	.error-message {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid var(--color-divine-error);
		border-radius: 0.75rem;
		padding: 1rem;
		margin-bottom: 1.5rem;
		color: var(--color-divine-error);
	}

	.error-message p {
		margin: 0 0 0.5rem 0;
	}

	.error-message p:last-child {
		margin-bottom: 0;
	}
</style>
