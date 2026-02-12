<script lang="ts">
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { setCurrentUser } from '$lib/current_user.svelte';
	import { BRAND } from '$lib/brand';
	import ndk from '$lib/ndk.svelte';
	import { signin, SigninMethod } from '$lib/utils/auth';
	import { PlugsConnected } from 'phosphor-svelte';

	const api = new KeycastApi();
	let isNip07Loading = $state(false);

	async function handleNip07Signin() {
		isNip07Loading = true;
		try {
			await signin(ndk, undefined, SigninMethod.Nip07);
		} catch (err) {
			console.error('NIP-07 signin error:', err);
		} finally {
			isNip07Loading = false;
		}
	}

	let email = $state('');
	let password = $state('');
	let isLoading = $state(false);
	let showVerificationNotice = $state(false);
	let unverifiedEmail = $state('');
	let isResending = $state(false);

	async function handleLogin() {
		if (!email || !password) {
			toast.error('Please enter both email and password');
			return;
		}

		// Reset verification notice
		showVerificationNotice = false;

		try {
			isLoading = true;

			// Simple REST login (not OAuth)
			// Returns JSON and sets UCAN cookie
			const response = await api.post<{
				success: boolean;
				pubkey: string;
			}>(
				'/auth/login',
				{ email, password }
			);

			toast.success('Login successful!');

			// Set current user for UI state (Header, navigation, etc.)
			setCurrentUser(response.pubkey, 'cookie');

			// UCAN token cookie is set, redirect to dashboard
			goto('/');
		} catch (err: any) {
			console.error('Login error:', err);

			// Check if this is an email not verified error
			if (err.code === 'EMAIL_NOT_VERIFIED' || err.verification_required) {
				showVerificationNotice = true;
				unverifiedEmail = err.email || email;
				toast.error('Please verify your email before logging in');
			} else {
				toast.error(err.message || 'Login failed. Please check your credentials.');
			}
		} finally {
			isLoading = false;
		}
	}

	async function handleResendVerification() {
		if (!unverifiedEmail) {
			toast.error('No email address available');
			return;
		}

		try {
			isResending = true;
			await api.post('/auth/resend-verification', { email: unverifiedEmail });
			toast.success('Verification email sent! Check your inbox.');
		} catch (err: any) {
			console.error('Resend error:', err);
			toast.error(err.message || 'Failed to resend verification email');
		} finally {
			isResending = false;
		}
	}
</script>

<svelte:head>
	<title>Login - {BRAND.name}</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<!-- Logo/Branding -->
		<a href="/" class="auth-branding">
			<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 256 256">
				<path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
			</svg>
			<span>{BRAND.name}</span>
		</a>

		<h1>Sign in</h1>
		<p class="subtitle">{BRAND.tagline}</p>

		{#if showVerificationNotice}
			<div class="verification-notice">
				<div class="notice-icon">
					<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 256 256">
						<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm-8,56a8,8,0,0,1,16,0v56a8,8,0,0,1-16,0Zm8,104a12,12,0,1,1,12-12A12,12,0,0,1,128,184Z"></path>
					</svg>
				</div>
				<div class="notice-content">
					<p><strong>Email verification required</strong></p>
					<p>Please check your inbox for a verification link.</p>
					<button
						type="button"
						class="btn-resend"
						onclick={handleResendVerification}
						disabled={isResending}
					>
						{isResending ? 'Sending...' : 'Resend verification email'}
					</button>
				</div>
			</div>
		{/if}

		<form onsubmit={(e) => { e.preventDefault(); handleLogin(); }}>
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
					placeholder="••••••••"
					required
					disabled={isLoading}
				/>
			</div>

			<button type="submit" class="btn-primary" disabled={isLoading}>
				{isLoading ? 'Signing in...' : 'Sign In'}
			</button>
		</form>

		<p class="auth-link">
			<a href="/forgot-password">Forgot password?</a>
		</p>

		<p class="auth-link">
			Don't have an account? <a href="/register">Create one</a>
		</p>

		<div class="auth-divider">
			<span>or</span>
		</div>

		<button
			class="btn-extension"
			onclick={handleNip07Signin}
			disabled={isNip07Loading}
		>
			<PlugsConnected size={18} />
			{isNip07Loading ? 'Connecting...' : 'Sign in with Extension (NIP-07)'}
		</button>
		<p class="auth-note">
			Team admins only. Requires whitelisted pubkey and browser extension (Alby, nos2x, etc.)
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
		flex-direction: row;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		font-family: var(--font-heading);
		font-size: 1.5rem;
		font-weight: 700;
		color: var(--color-divine-green);
		text-decoration: none;
		margin-bottom: 1.5rem;
	}

	.auth-branding:hover {
		color: var(--color-divine-green-dark);
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

	.auth-divider {
		display: flex;
		align-items: center;
		margin: 1.5rem 0 1rem;
	}

	.auth-divider::before,
	.auth-divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--color-divine-border);
	}

	.auth-divider span {
		padding: 0 1rem;
		color: var(--color-divine-text-tertiary);
		font-size: 0.8rem;
	}

	.btn-extension {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		padding: 0.75rem 1.5rem;
		background: transparent;
		border: 1px solid var(--color-divine-border);
		border-radius: 9999px;
		color: var(--color-divine-text-secondary);
		font-size: 0.95rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
	}

	.btn-extension:hover:not(:disabled) {
		border-color: var(--color-divine-green);
		color: var(--color-divine-green);
	}

	.btn-extension:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.auth-note {
		text-align: center;
		margin-top: 0.75rem;
		color: var(--color-divine-text-tertiary);
		font-size: 0.75rem;
	}

	.verification-notice {
		display: flex;
		gap: 0.75rem;
		padding: 1rem;
		background: rgba(255, 193, 7, 0.1);
		border: 1px solid rgba(255, 193, 7, 0.3);
		border-radius: 0.5rem;
		margin-bottom: 1.5rem;
	}

	.notice-icon {
		color: #f59e0b;
		flex-shrink: 0;
		padding-top: 0.125rem;
	}

	.notice-content {
		flex: 1;
	}

	.notice-content p {
		margin: 0;
		font-size: 0.875rem;
		color: var(--color-divine-text);
	}

	.notice-content p:first-child {
		margin-bottom: 0.25rem;
	}

	.btn-resend {
		background: none;
		border: none;
		color: var(--color-divine-green);
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		padding: 0;
		margin-top: 0.5rem;
		text-decoration: underline;
	}

	.btn-resend:hover:not(:disabled) {
		color: var(--color-divine-green-dark);
	}

	.btn-resend:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
