<script lang="ts">
	import QR from '@svelte-put/qr/svg/QR.svelte';
	import { createQrSvgDataUrl } from '@svelte-put/qr';

	interface Props {
		data: string;
		size?: number;
		downloadable?: boolean;
		downloadFilename?: string;
	}

	let { data, size = 200, downloadable = false, downloadFilename = 'bunker-qr' }: Props = $props();

	function downloadQR() {
		const dataUrl = createQrSvgDataUrl({ data });
		const link = document.createElement('a');
		link.href = dataUrl;
		link.download = `${downloadFilename}.svg`;
		document.body.appendChild(link);
		link.click();
		document.body.removeChild(link);
	}
</script>

<div class="qr-container">
	<div class="qr-wrapper" style="width: {size}px; height: {size}px;">
		<QR
			{data}
			moduleFill="#1a1a1a"
			anchorOuterFill="#1a1a1a"
			anchorInnerFill="#1a1a1a"
		/>
	</div>
	{#if downloadable}
		<button class="download-btn" onclick={downloadQR}>
			Download QR Code
		</button>
	{/if}
</div>

<style>
	.qr-container {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
	}

	.qr-wrapper {
		background: white;
		padding: 12px;
		border-radius: var(--radius-md, 8px);
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.qr-wrapper :global(svg) {
		width: 100%;
		height: 100%;
	}

	.download-btn {
		padding: 0.5rem 1rem;
		background: transparent;
		color: var(--color-divine-text-secondary, #999);
		border: 1px solid var(--color-divine-border, #333);
		border-radius: var(--radius-md, 8px);
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.download-btn:hover {
		background: var(--color-divine-border, #333);
		color: var(--color-divine-text, #fff);
	}
</style>
