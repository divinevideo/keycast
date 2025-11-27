<script lang="ts">
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { setCurrentUser } from '$lib/current_user.svelte';
	import { BRAND } from '$lib/brand';

	const api = new KeycastApi();

	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let isLoading = $state(false);

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

			const response = await api.post<{ token: string; pubkey: string; email: string }>(
				'/auth/register',
				{ email, password }
			);

			toast.success(`Account created! Welcome ${email}`);

			// Set current user for UI state (Header, navigation, etc.)
			setCurrentUser(response.pubkey, 'cookie');

			// Cookie is set, redirect to dashboard
			goto('/');
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
			<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" viewBox="0 0 256 256">
				<path d="M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM180,92a16,16,0,1,1,16-16A16,16,0,0,1,180,92Z"></path>
			</svg>
			<span>{BRAND.name}</span>
		</a>

		<h1>Create your {BRAND.name}</h1>
		<p class="subtitle">{BRAND.tagline}</p>

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

			<button type="submit" class="btn-primary" disabled={isLoading}>
				{isLoading ? 'Creating account...' : 'Create Account'}
			</button>
		</form>

		<p class="auth-link">
			Already have an account? <a href="/login">Sign in</a>
		</p>

		<p class="auth-note">
			Team admins: Use <a href="/">NIP-07 browser extension</a> instead
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
		box-shadow: 0 2px 8px rgba(0, 180, 136, 0.08);
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
		box-shadow: 0 0 0 2px rgba(0, 180, 136, 0.2);
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
		box-shadow: 0 2px 8px rgba(0, 180, 136, 0.16);
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
</style>
