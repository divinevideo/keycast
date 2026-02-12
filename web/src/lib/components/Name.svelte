<script lang="ts">
import { nip19 } from "nostr-tools";

let { pubkey, npubMaxLength = 9 }: { pubkey: string; npubMaxLength?: number } = $props();

let displayName = $derived(nip19.npubEncode(pubkey).slice(0, npubMaxLength));
</script>

{displayName}
