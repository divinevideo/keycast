<script lang="ts">
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { setCurrentUser } from '$lib/current_user.svelte';
	import { BRAND } from '$lib/brand';
	import { onMount } from 'svelte';

	const api = new KeycastApi();
	let hasExtension = $state(false);

	onMount(() => {
		hasExtension = typeof window !== 'undefined' && !!window.nostr;
	});

	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let nsec = $state('');
	let showAdvanced = $state(false);
	let isLoading = $state(false);
	let showVerificationNotice = $state(false);
	let registeredEmail = $state('');

	async function handleRegister() {
		if (!email || !password) {
			toast.error('Please enter email and password');
			return;
		}

		if (password.length < 8) {
			toast.error('Password must be at least 8 characters');
			return;
		}

		if (password !== confirmPassword) {
			toast.error('Passwords do not match');
			return;
		}

		try {
			isLoading = true;

			const body: Record<string, string> = { email, password };
			if (nsec.trim()) body.nsec = nsec.trim();

			const response = await api.post<{
				success?: boolean;
				verification_required?: boolean;
				token?: string;
				pubkey?: string;
				email?: string;
			}>('/auth/register', body);

			// Check if email verification is required
			if (response.verification_required) {
				showVerificationNotice = true;
				registeredEmail = response.email || email;
				toast.success('Account created! Please verify your email.');
				return;
			}

			// Legacy flow: immediate login
			if (response.pubkey) {
				toast.success(`Account created! Welcome ${email}`);
				setCurrentUser(response.pubkey, 'cookie');
				goto('/');
			}
		} catch (err: any) {
			console.error('Registration error:', err);
			toast.error(err.message || 'Registration failed. Please try again.');
		} finally {
			isLoading = false;
		}
	}
</script>

<svelte:head>
	<title>Register - {BRAND.name}</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<!-- Logo/Branding -->
		<a href="/" class="auth-branding">
			<img src="/divine-logo.svg" alt="{BRAND.shortName}" class="auth-logo-img" />
			<span class="auth-logo-sub">Login</span>
		</a>

		<h1>Create your account</h1>
		<p class="subtitle">Your Nostr identity, simplified</p>

		{#if showVerificationNotice}
			<div class="verification-notice">
				<div class="notice-icon success">
					<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
						<path d="M224,48H32a8,8,0,0,0-8,8V192a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A8,8,0,0,0,224,48ZM203.43,64,128,133.15,52.57,64ZM216,192H40V74.19l82.59,75.71a8,8,0,0,0,10.82,0L216,74.19V192Z"></path>
					</svg>
				</div>
				<h2>Check your email</h2>
				<p>We've sent a verification link to <strong>{registeredEmail}</strong></p>
				<p class="subtext">Click the link in the email to verify your account and sign&nbsp;in.</p>
				<a href="/login" class="btn-secondary">Go to Login</a>
			</div>
		{:else}
			<form onsubmit={(e) => { e.preventDefault(); handleRegister(); }}>
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

			<div class="form-group">
				<label for="password">Password</label>
				<input
					id="password"
					type="password"
					bind:value={password}
					placeholder="At least 8 characters"
					required
					minlength="8"
					disabled={isLoading}
				/>
			</div>

			<div class="form-group">
				<label for="confirm-password">Confirm Password</label>
				<input
					id="confirm-password"
					type="password"
					bind:value={confirmPassword}
					placeholder="Re-enter password"
					required
					minlength="8"
					disabled={isLoading}
				/>
			</div>

			<button
				type="button"
				class="advanced-toggle"
				onclick={() => showAdvanced = !showAdvanced}
			>
				Already have a Nostr account?
				<span class="toggle-arrow" class:open={showAdvanced}>&rsaquo;</span>
			</button>

			{#if showAdvanced}
			<div class="advanced-section">
				<div class="form-group">
					<label for="nsec">Your Nostr private key</label>
					<input
						id="nsec"
						type="password"
						bind:value={nsec}
						placeholder="nsec1... or hex format"
						autocomplete="off"
						disabled={isLoading}
					/>
					<p class="field-hint">Import your existing key to use it with diVine Login. Leave empty to create a new one.</p>
				</div>
			</div>
			{/if}

			<button type="submit" class="btn-primary" disabled={isLoading}>
				{isLoading ? 'Creating account...' : 'Create Account'}
			</button>
		</form>

			<p class="auth-link">
				Already have an account? <a href="/login">Sign in</a>
			</p>

			{#if hasExtension}
			<p class="auth-note">
				Admin? <a href="/login">Sign in with your Nostr extension</a>
			</p>
			{/if}
		{/if}
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

	.advanced-toggle {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.25rem;
		width: 100%;
		background: none;
		border: none;
		color: var(--color-divine-text-secondary);
		font-size: 0.8rem;
		cursor: pointer;
		padding: 0.25rem 0;
		margin-bottom: 0.5rem;
		transition: color 0.2s;
	}

	.advanced-toggle:hover {
		color: var(--color-divine-green);
	}

	.toggle-arrow {
		display: inline-block;
		transition: transform 0.2s;
		font-size: 1rem;
	}

	.toggle-arrow.open {
		transform: rotate(90deg);
	}

	.advanced-section {
		margin-bottom: 0.5rem;
	}

	.field-hint {
		font-size: 0.75rem;
		color: var(--color-divine-text-secondary);
		margin-top: 0.35rem;
		line-height: 1.4;
	}

	.btn-primary {
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

	.auth-note {
		text-align: center;
		margin-top: 1.5rem;
		padding-top: 1.25rem;
		border-top: 1px solid var(--color-divine-border);
		color: var(--color-divine-text-tertiary);
		font-size: 0.8rem;
	}

	.auth-note a {
		color: var(--color-divine-green);
		text-decoration: none;
	}

	.auth-note a:hover {
		text-decoration: underline;
	}

	.verification-notice {
		text-align: center;
		padding: 1rem 0;
	}

	.verification-notice .notice-icon {
		display: flex;
		justify-content: center;
		margin-bottom: 1rem;
	}

	.verification-notice .notice-icon.success {
		color: var(--color-divine-green);
	}

	.verification-notice h2 {
		font-size: 1.25rem;
		font-weight: 600;
		color: var(--color-divine-text);
		margin-bottom: 0.5rem;
	}

	.verification-notice p {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		line-height: 1.5;
		margin-bottom: 0.5rem;
	}

	.verification-notice strong {
		color: var(--color-divine-text);
	}

	.verification-notice .subtext {
		font-size: 0.8rem;
		margin-bottom: 1.5rem;
	}

	.btn-secondary {
		display: inline-block;
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
