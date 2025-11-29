<script lang="ts">
import Copy from "$lib/components/Copy.svelte";
import { CircleNotch, CheckCircle, XCircle } from "phosphor-svelte";
import { onMount } from "svelte";

type Status = 'idle' | 'loading' | 'success' | 'error';

let {
    status = 'idle',
    result = null,
    error = null,
    label = 'Result'
}: {
    status?: Status;
    result?: string | object | null;
    error?: string | null;
    label?: string;
} = $props();

// Check if result is a hex pubkey (64 hex chars)
const isHexPubkey = $derived(
    typeof result === 'string' && /^[0-9a-f]{64}$/i.test(result)
);

let npubVersion = $state<string | null>(null);

// Convert hex pubkey to npub
$effect(() => {
    if (isHexPubkey && typeof result === 'string') {
        // Reset first in case of re-render
        npubVersion = null;
        import('nostr-tools/nip19').then(({ npubEncode }) => {
            try {
                npubVersion = npubEncode(result);
            } catch (e) {
                console.error('Failed to encode npub:', e);
                npubVersion = null;
            }
        }).catch(e => {
            console.error('Failed to load nip19:', e);
        });
    } else {
        npubVersion = null;
    }
});

const formattedResult = $derived(
    result !== null
        ? (typeof result === 'object' ? JSON.stringify(result, null, 2) : String(result))
        : null
);
</script>

{#if status !== 'idle'}
    <div class="result-display" class:success={status === 'success'} class:error={status === 'error'}>
        <div class="result-header">
            <span class="result-label">
                {#if status === 'loading'}
                    <CircleNotch size={16} class="animate-spin" />
                {:else if status === 'success'}
                    <CheckCircle size={16} weight="fill" class="text-divine-success" />
                {:else if status === 'error'}
                    <XCircle size={16} weight="fill" class="text-divine-error" />
                {/if}
                {label}
            </span>
            {#if status === 'success' && formattedResult}
                <Copy value={formattedResult} size="16" />
            {/if}
        </div>

        {#if status === 'loading'}
            <span class="loading-text">Processing...</span>
        {:else if status === 'error' && error}
            <span class="error-text">{error}</span>
        {:else if status === 'success' && formattedResult}
            {#if isHexPubkey}
                <div class="pubkey-display">
                    <div class="pubkey-row">
                        <span class="pubkey-label">hex</span>
                        <code class="pubkey-value">{formattedResult}</code>
                        <Copy value={formattedResult} size="14" />
                    </div>
                    <div class="pubkey-row">
                        <span class="pubkey-label">npub</span>
                        {#if npubVersion}
                            <code class="pubkey-value">{npubVersion}</code>
                            <Copy value={npubVersion} size="14" />
                        {:else}
                            <code class="pubkey-value loading">loading...</code>
                        {/if}
                    </div>
                </div>
            {:else}
                <pre class="result-content">{formattedResult}</pre>
            {/if}
        {/if}
    </div>
{/if}

<style>
    .result-display {
        margin-top: 1rem;
        padding: 1rem;
        border-radius: var(--radius-lg);
        font-family: var(--font-mono);
        font-size: 0.875rem;
        background: var(--color-divine-muted);
        border: 1px solid var(--color-divine-border);
    }

    .result-display.success {
        border-color: var(--color-divine-success);
    }

    .result-display.error {
        border-color: var(--color-divine-error);
    }

    .result-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 0.5rem;
        font-family: var(--font-sans);
        font-size: 0.75rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--color-divine-text-secondary);
    }

    .result-label {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .loading-text {
        color: var(--color-divine-text-secondary);
    }

    .error-text {
        color: var(--color-divine-error);
    }

    .result-content {
        margin: 0;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 300px;
        overflow-y: auto;
    }

    .text-divine-success {
        color: var(--color-divine-success);
    }

    .text-divine-error {
        color: var(--color-divine-error);
    }

    :global(.animate-spin) {
        animation: spin 1s linear infinite;
    }

    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }

    .pubkey-display {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .pubkey-row {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem;
        background: var(--color-divine-surface);
        border-radius: var(--radius-sm);
    }

    .pubkey-label {
        font-family: var(--font-sans);
        font-weight: 500;
        font-size: 0.75rem;
        color: var(--color-divine-text-secondary);
        text-transform: uppercase;
        min-width: 3rem;
    }

    .pubkey-value {
        flex: 1;
        font-family: var(--font-mono);
        font-size: 0.75rem;
        word-break: break-all;
        color: var(--color-divine-text);
    }

    .pubkey-value.loading {
        color: var(--color-divine-text-tertiary);
        font-style: italic;
    }
</style>
