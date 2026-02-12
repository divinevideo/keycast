<script lang="ts">
let { pubkey, extraClasses }: { pubkey: string; extraClasses: string } = $props();
</script>

<img src="https://robohash.org/{pubkey}" alt="Avatar" class="object-cover rounded-full {extraClasses} ring-1 ring-gray-300 dark:ring-gray-500" />
