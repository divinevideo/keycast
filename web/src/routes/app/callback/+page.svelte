<script lang="ts">
// ABOUTME: OAuth callback fallback page for iOS/Android Universal Links
// ABOUTME: Users only see this if Universal Link fails - tap button to retry
import { page } from "$app/stores";
import { browser } from "$app/environment";

const currentUrl = $derived(browser ? $page.url.href : "");
</script>

<svelte:head>
    <title>Returning to App - Keycast</title>
    <meta name="robots" content="noindex">
</svelte:head>

<div class="callback-container">
    <div class="callback-card">
        <div class="icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                <polyline points="16 17 21 12 16 7"/>
                <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
        </div>

        <h1>Authentication Complete</h1>
        <p>Tap the button below to return to the app.</p>

        <a href={currentUrl} class="open-app-button">
            Open in App
        </a>

        <p class="hint">
            If the app doesn't open, make sure the app is installed.
        </p>
    </div>
</div>

<style>
    .callback-container {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 1rem;
        background: var(--color-divine-bg);
    }

    .callback-card {
        max-width: 400px;
        width: 100%;
        text-align: center;
        padding: 2.5rem 2rem;
        background: var(--color-divine-surface);
        border: 1px solid var(--color-divine-border);
        border-radius: 1rem;
        box-shadow: var(--shadow-md);
    }

    .icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 80px;
        height: 80px;
        border-radius: 50%;
        background: rgba(0, 180, 136, 0.1);
        color: var(--color-divine-green);
        margin-bottom: 1.5rem;
    }

    h1 {
        font-size: 1.5rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
        color: var(--color-divine-text);
    }

    p {
        color: var(--color-divine-text-secondary);
        margin-bottom: 1.5rem;
    }

    .open-app-button {
        display: inline-block;
        padding: 0.875rem 2rem;
        font-size: 1rem;
        font-weight: 600;
        color: white;
        background: var(--color-divine-green);
        border-radius: 9999px;
        text-decoration: none;
        transition: background 0.2s, box-shadow 0.2s;
    }

    .open-app-button:hover {
        background: var(--color-divine-green-dark);
        box-shadow: var(--shadow-sm);
    }

    .hint {
        font-size: 0.875rem;
        color: var(--color-divine-text-tertiary);
        margin-top: 1.5rem;
        margin-bottom: 0;
    }
</style>
