<script lang="ts">
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';

	const api = new KeycastApi();

	let email = $state('');
	let isLoading = $state(false);
	let emailSent = $state(false);

	async function handleSubmit() {
		if (!email) {
			toast.error('Please enter your email address');
			return;
		}

		try {
			isLoading = true;

			await api.post('/auth/forgot-password', { email });

			emailSent = true;
			toast.success('Check your email for a reset link');
		} catch (err: any) {
			console.error('Forgot password error:', err);
			toast.error(err.message || 'Something went wrong. Please try again.');
		} finally {
			isLoading = false;
		}
	}
</script>

<svelte:head>
	<title>Forgot Password - {BRAND.name}</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<a href="/" class="auth-branding">
			<img src="/divine-logo.svg" alt="{BRAND.shortName}" class="auth-logo-img" />
			<span class="auth-logo-sub">Login</span>
		</a>

		<h1>Forgot Password</h1>
		<p class="subtitle">Enter your email and we'll send you a reset link</p>

		{#if emailSent}
			<div class="success-message">
				<p>If an account exists with that email, you'll receive a password reset link shortly.</p>
				<p>Check your inbox and spam folder.</p>
			</div>
			<a href="/login" class="btn-primary">Back to Login</a>
		{:else}
			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
				<div class="form-group">
					<label for="email">Email</label>
					<input
						id="email"
						type="email"
						bind:value={email}
						placeholder="you@example.com"
						required
						disabled={isLoading}
					/>
				</div>

				<button type="submit" class="btn-primary" disabled={isLoading}>
					{isLoading ? 'Sending...' : 'Send Reset Link'}
				</button>
			</form>
		{/if}

		<p class="auth-link">
			Remember your password? <a href="/login">Sign in</a>
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

	.form-group {
		margin-bottom: 1rem;
	}

	label {
		display: block;
		margin-bottom: 0.375rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.875rem;
		font-weight: 500;
	}

	input {
		width: 100%;
		padding: 0.75rem 1rem;
		background: var(--color-divine-muted);
		border: 1px solid var(--color-divine-border);
		border-radius: 0.5rem;
		color: var(--color-divine-text);
		font-size: 1rem;
		box-sizing: border-box;
		transition: border-color 0.2s, box-shadow 0.2s;
	}

	input:focus {
		outline: none;
		border-color: var(--color-divine-green);
		box-shadow: 0 0 0 2px rgba(39, 197, 139, 0.2);
	}

	input::placeholder {
		color: var(--color-divine-text-secondary);
		opacity: 0.6;
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		display: block;
		width: 100%;
		padding: 0.75rem 1.5rem;
		background: var(--color-divine-green);
		color: white;
		border: none;
		border-radius: 9999px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
		text-align: center;
		text-decoration: none;
		margin-top: 0.5rem;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--color-divine-green-dark);
		box-shadow: 0 2px 8px rgba(39, 197, 139, 0.16);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
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

	.success-message {
		background: rgba(39, 197, 139, 0.1);
		border: 1px solid rgba(39, 197, 139, 0.3);
		border-radius: 0.75rem;
		padding: 1rem;
		margin-bottom: 1.5rem;
		color: var(--color-divine-green);
	}

	.success-message p {
		margin: 0 0 0.5rem 0;
	}

	.success-message p:last-child {
		margin-bottom: 0;
	}
</style>
