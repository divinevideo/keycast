<script lang="ts">
import type { Snippet } from "svelte";
import Tooltip from "$lib/components/Tooltip.svelte";

let {
    title,
    description = null,
    tooltip = null,
    children
}: {
    title: string;
    description?: string | null;
    tooltip?: string | null;
    children: Snippet;
} = $props();
</script>

<section class="demo-section">
    <div class="section-header">
        <h2 class="section-title">
            {title}
            {#if tooltip}
                <Tooltip content={tooltip} size={16} />
            {/if}
        </h2>
        {#if description}
            <p class="section-description">{description}</p>
        {/if}
    </div>
    <div class="section-content">
        {@render children()}
    </div>
</section>

<style>
    .demo-section {
        margin-bottom: 2rem;
        padding: 1.5rem;
        border-radius: var(--radius-xl);
        background: var(--color-divine-surface);
        border: 1px solid var(--color-divine-border);
    }

    .section-header {
        margin-bottom: 1.5rem;
    }

    .section-title {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin: 0;
        font-size: 1.25rem;
        font-weight: 600;
        color: var(--color-divine-text);
    }

    .section-description {
        margin: 0.5rem 0 0 0;
        font-size: 0.875rem;
        color: var(--color-divine-text-secondary);
    }

    .section-content {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }
</style>
