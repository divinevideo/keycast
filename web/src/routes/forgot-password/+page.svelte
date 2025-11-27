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
			<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 256 256">
				<path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
			</svg>
			<span>{BRAND.name}</span>
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
		padding: 2rem;
	}

	.auth-container {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		padding: 3rem;
		max-width: 450px;
		width: 100%;
	}

	.auth-branding {
		display: flex;
		flex-direction: row;
		align-items: center;
		gap: 0.75rem;
		font-size: 1.5rem;
		font-weight: 700;
		color: #e0e0e0;
		text-decoration: none;
		margin-bottom: 2rem;
	}

	.auth-branding:hover {
		color: #fff;
	}

	h1 {
		margin: 0 0 0.5rem 0;
		color: #e0e0e0;
		font-size: 1.5rem;
	}

	.subtitle {
		color: #999;
		margin: 0 0 2rem 0;
	}

	.form-group {
		margin-bottom: 1.5rem;
	}

	label {
		display: block;
		margin-bottom: 0.5rem;
		color: #e0e0e0;
		font-size: 0.9rem;
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
		border-color: var(--color-divine-purple);
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		display: block;
		width: 100%;
		padding: 0.75rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.2s;
		text-align: center;
		text-decoration: none;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--color-divine-green-dark);
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.auth-link {
		text-align: center;
		margin-top: 1.5rem;
		color: #999;
	}

	.auth-link a {
		color: var(--color-divine-purple-light);
		text-decoration: none;
	}

	.auth-link a:hover {
		text-decoration: underline;
	}

	.success-message {
		background: rgba(34, 197, 94, 0.1);
		border: 1px solid rgba(34, 197, 94, 0.3);
		border-radius: 6px;
		padding: 1rem;
		margin-bottom: 1.5rem;
		color: #86efac;
	}

	.success-message p {
		margin: 0 0 0.5rem 0;
	}

	.success-message p:last-child {
		margin-bottom: 0;
	}
</style>
