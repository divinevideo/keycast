import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

const keycastLoginEntry = new URL("../keycast-login/dist/index.mjs", import.meta.url).pathname;

export default defineConfig({
    plugins: [sveltekit()],
    resolve: {
        alias: {
            // Explicit alias for Docker builds where symlinks don't work
            // Use .mjs (ESM) version for compatibility with Vite/Rollup
            "keycast-login": keycastLoginEntry,
        },
    },
    optimizeDeps: {
        include: ["nostr-tools", "nostr-tools/pure", "nostr-tools/nip19"],
    },
    server: {
        proxy: {
            '/api': {
                target: 'http://localhost:3000',
                changeOrigin: true
            }
        }
    },
    build: {
        target: "esnext",
        minify: "esbuild",
        rollupOptions: {
            output: {
                sanitizeFileName: (name: string) => {
                    return name.replace(/[<>*#"{}|^[\]`;?:&=+$,]/g, "_");
                },
            },
        },
    },
    esbuild: {
        charset: "utf8",
    },
});
