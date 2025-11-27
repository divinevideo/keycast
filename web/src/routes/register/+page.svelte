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

	.auth-note {
		text-align: center;
		margin-top: 2rem;
		padding-top: 1.5rem;
		border-top: 1px solid #333;
		color: #666;
		font-size: 0.85rem;
	}

	.auth-note a {
		color: var(--color-divine-green);
		text-decoration: none;
	}

	.auth-note a:hover {
		text-decoration: underline;
	}
</style>
