<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';

	let swaggerContainer: HTMLDivElement;

	onMount(async () => {
		if (browser) {
			// Dynamically import Swagger UI for client-side rendering
			// @ts-ignore - swagger-ui-dist doesn't have TypeScript declarations
			const SwaggerUIBundle = (await import('swagger-ui-dist/swagger-ui-bundle.js')).default;
			// @ts-ignore - swagger-ui-dist doesn't have TypeScript declarations
			const SwaggerUIStandalonePreset = (await import('swagger-ui-dist/swagger-ui-standalone-preset.js')).default;

			SwaggerUIBundle({
				url: '/api/docs/openapi.json',
				dom_id: '#swagger-ui',
				deepLinking: true,
				presets: [
					SwaggerUIBundle.presets.apis,
					SwaggerUIStandalonePreset
				],
				plugins: [
					SwaggerUIBundle.plugins.DownloadUrl
				],
				layout: 'StandaloneLayout',
				tryItOutEnabled: true,
				persistAuthorization: false
			});
		}
	});
</script>

<svelte:head>
	<title>Keycast API Documentation</title>
	<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</svelte:head>

<div class="docs-container">
	<div class="docs-header">
		<h1>🔑 Keycast HTTP API Documentation</h1>
		<p class="subtitle">
			Fast HTTP signing for Nostr events | <a href="https://github.com/rabble/keycast" target="_blank">GitHub</a>
		</p>
	</div>

	<div id="swagger-ui" bind:this={swaggerContainer}></div>
</div>

<style>
	:global(body) {
		margin: 0;
		padding: 0;
	}

	.docs-container {
		min-height: 100vh;
		background: #1a1a1a;
	}

	.docs-header {
		background: linear-gradient(135deg, #bb86fc 0%, #03dac6 100%);
		padding: 2rem;
		text-align: center;
		color: #000;
	}

	.docs-header h1 {
		margin: 0;
		font-size: 2.5rem;
		font-weight: 700;
	}

	.subtitle {
		margin: 0.5rem 0 0 0;
		font-size: 1.1rem;
		opacity: 0.9;
	}

	.subtitle a {
		color: #000;
		text-decoration: underline;
	}

	.subtitle a:hover {
		opacity: 0.8;
	}

	#swagger-ui {
		max-width: 1400px;
		margin: 0 auto;
		padding: 2rem;
	}

	/* Dark theme overrides for Swagger UI */
	:global(#swagger-ui .swagger-ui) {
		color: #e0e0e0;
	}

	:global(#swagger-ui .swagger-ui .opblock-tag) {
		color: #e0e0e0;
		border-bottom-color: #444;
	}

	:global(#swagger-ui .swagger-ui .opblock) {
		background: rgba(42, 42, 42, 0.8);
		border-color: #444;
	}

	:global(#swagger-ui .swagger-ui .opblock .opblock-summary) {
		border-color: #444;
	}

	:global(#swagger-ui .swagger-ui .opblock .opblock-summary-description) {
		color: #e0e0e0;
	}

	:global(#swagger-ui .swagger-ui .opblock-description-wrapper p) {
		color: #e0e0e0;
	}

	:global(#swagger-ui .swagger-ui .parameter__name) {
		color: #bb86fc;
	}

	:global(#swagger-ui .swagger-ui .response-col_status) {
		color: #03dac6;
	}

	:global(#swagger-ui .swagger-ui table thead tr th) {
		color: #e0e0e0;
		border-color: #444;
	}

	:global(#swagger-ui .swagger-ui .model-box) {
		background: rgba(42, 42, 42, 0.6);
	}

	:global(#swagger-ui .swagger-ui .information-container) {
		background: rgba(42, 42, 42, 0.6);
		color: #e0e0e0;
	}
</style>
