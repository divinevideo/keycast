<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	type Props = {
		id?: string;
		name?: string;
		value?: string;
		placeholder?: string;
		autocomplete?: HTMLInputAttributes['autocomplete'];
		required?: boolean;
		minlength?: number;
		disabled?: boolean;
		readonly?: boolean;
		class?: string;
		onkeydown?: (event: KeyboardEvent) => void;
	};

	let {
		id,
		name,
		value = $bindable(''),
		placeholder,
		autocomplete,
		required = false,
		minlength,
		disabled = false,
		readonly = false,
		class: className = '',
		onkeydown
	}: Props = $props();

	let isVisible = $state(false);
	const toggleLabel = $derived(isVisible ? 'Hide password' : 'Show password');
</script>

<div class="password-input-wrapper">
	<input
		{id}
		{name}
		type={isVisible ? 'text' : 'password'}
		bind:value
		{placeholder}
		{autocomplete}
		{required}
		{minlength}
		{disabled}
		{readonly}
		class={className}
		onkeydown={onkeydown}
	/>
	<button
		type="button"
		class="password-toggle"
		aria-label={toggleLabel}
		title={toggleLabel}
		onclick={() => (isVisible = !isVisible)}
		disabled={disabled}
	>
		{isVisible ? 'Hide' : 'Show'}
	</button>
</div>

<style>
	.password-input-wrapper {
		position: relative;
		width: 100%;
	}

	input {
		width: 100%;
		padding: 0.75rem 4.75rem 0.75rem 1rem;
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

	.password-toggle {
		position: absolute;
		top: 50%;
		right: 0.5rem;
		transform: translateY(-50%);
		padding: 0.25rem 0.5rem;
		background: transparent;
		border: 1px solid transparent;
		border-radius: 9999px;
		color: var(--color-divine-text-secondary);
		font-size: 0.75rem;
		font-weight: 600;
		cursor: pointer;
	}

	.password-toggle:hover:not(:disabled),
	.password-toggle:focus-visible:not(:disabled) {
		color: var(--color-divine-green);
		border-color: var(--color-divine-border);
		outline: none;
	}

	.password-toggle:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
