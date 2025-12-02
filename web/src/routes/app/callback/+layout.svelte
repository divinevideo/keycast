<script lang="ts">
// ABOUTME: Standalone layout for mobile app OAuth callback
// ABOUTME: No header/nav - this page only serves as Universal Links fallback
import "../../../app.css";

let { children }: { children: any } = $props();
</script>

{@render children()}
