<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';

	const api = new KeycastApi();

	let status = $state<'loading' | 'success' | 'error' | 'no-token'>('loading');
	let message = $state('');

	onMount(async () => {
		const token = $page.url.searchParams.get('token');

		if (!token) {
			status = 'no-token';
			message = 'No verification token provided';
			return;
		}

		try {
			const response = await api.post<{ success: boolean; message: string }>(
				'/auth/verify-email',
				{ token }
			);

			if (response.success) {
				status = 'success';
				message = response.message || 'Email verified successfully!';
				toast.success('Email verified!');

				// Redirect to login after 3 seconds
				setTimeout(() => {
					goto('/login');
				}, 3000);
			} else {
				status = 'error';
				message = response.message || 'Verification failed';
			}
		} catch (err: any) {
			console.error('Verification error:', err);
			status = 'error';
			message = err.message || 'Verification failed. The link may have expired.';
		}
	});
</script>

<svelte:head>
	<title>Verify Email - {BRAND.name}</title>
</svelte:head>

<div class="verify-page">
	<div class="verify-container">
		<!-- Logo/Branding -->
		<a href="/" class="verify-branding">
			<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 256 256">
				<path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
			</svg>
			<span>{BRAND.name}</span>
		</a>

		{#if status === 'loading'}
			<div class="status-icon loading">
				<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256" class="spin">
					<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,176A72,72,0,1,1,200,128,72.08,72.08,0,0,1,128,200Z" opacity="0.2"></path>
					<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,16a88,88,0,0,1,88,88h-16a72,72,0,0,0-72-72Z"></path>
				</svg>
			</div>
			<h1>Verifying your email...</h1>
			<p class="subtitle">Please wait</p>

		{:else if status === 'success'}
			<div class="status-icon success">
				<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
					<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm45.66,85.66-56,56a8,8,0,0,1-11.32,0l-24-24a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32Z"></path>
				</svg>
			</div>
			<h1>Email Verified!</h1>
			<p class="subtitle">{message}</p>
			<p class="redirect-notice">Redirecting to login...</p>
			<a href="/login" class="btn-primary">Go to Login</a>

		{:else if status === 'error'}
			<div class="status-icon error">
				<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
					<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm37.66,130.34a8,8,0,0,1-11.32,11.32L128,139.31l-26.34,26.35a8,8,0,0,1-11.32-11.32L116.69,128,90.34,101.66a8,8,0,0,1,11.32-11.32L128,116.69l26.34-26.35a8,8,0,0,1,11.32,11.32L139.31,128Z"></path>
				</svg>
			</div>
			<h1>Verification Failed</h1>
			<p class="subtitle">{message}</p>
			<div class="actions">
				<a href="/login" class="btn-secondary">Go to Login</a>
				<a href="/register" class="btn-primary">Create New Account</a>
			</div>

		{:else if status === 'no-token'}
			<div class="status-icon error">
				<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
					<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm-8,56a8,8,0,0,1,16,0v56a8,8,0,0,1-16,0Zm8,104a12,12,0,1,1,12-12A12,12,0,0,1,128,184Z"></path>
				</svg>
			</div>
			<h1>Invalid Link</h1>
			<p class="subtitle">This verification link is invalid or incomplete.</p>
			<div class="actions">
				<a href="/login" class="btn-secondary">Go to Login</a>
				<a href="/register" class="btn-primary">Create New Account</a>
			</div>
		{/if}
	</div>
</div>

<style>
	.verify-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 1rem;
		background: var(--color-divine-bg);
	}

	.verify-container {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 1rem;
		padding: 2rem;
		max-width: 420px;
		width: 100%;
		text-align: center;
		box-shadow: 0 2px 8px rgba(0, 180, 136, 0.08);
	}

	.verify-branding {
		display: inline-flex;
		flex-direction: row;
		align-items: center;
		gap: 0.5rem;
		font-family: var(--font-heading);
		font-size: 1.5rem;
		font-weight: 700;
		color: var(--color-divine-green);
		text-decoration: none;
		margin-bottom: 1.5rem;
	}

	.verify-branding:hover {
		color: var(--color-divine-green-dark);
	}

	.status-icon {
		margin-bottom: 1.25rem;
	}

	.status-icon.loading {
		color: var(--color-divine-green);
	}

	.status-icon.success {
		color: var(--color-divine-green);
	}

	.status-icon.error {
		color: var(--color-divine-error);
	}

	.spin {
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}

	h1 {
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-text);
		font-family: var(--font-heading);
		font-size: 1.5rem;
		font-weight: 700;
	}

	.subtitle {
		color: var(--color-divine-text-secondary);
		margin: 0 0 1.25rem 0;
		font-size: 0.95rem;
	}

	.redirect-notice {
		color: var(--color-divine-text-tertiary);
		font-size: 0.85rem;
		margin-bottom: 1.25rem;
	}

	.actions {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.btn-primary {
		display: block;
		padding: 0.75rem 1.5rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 9999px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		text-decoration: none;
		transition: all 0.2s;
	}

	.btn-primary:hover {
		background: var(--color-divine-green-dark);
		box-shadow: 0 2px 8px rgba(0, 180, 136, 0.16);
	}

	.btn-secondary {
		display: block;
		padding: 0.75rem 1.5rem;
		background: transparent;
		color: var(--color-divine-text-secondary);
		border: 1px solid var(--color-divine-border);
		border-radius: 9999px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		text-decoration: none;
		transition: all 0.2s;
	}

	.btn-secondary:hover {
		background: var(--color-divine-muted);
		color: var(--color-divine-text);
	}
</style>
