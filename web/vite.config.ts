import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";
import path from "path";

export default defineConfig({
    plugins: [sveltekit()],
    resolve: {
        alias: {
            // Explicit alias for Docker builds where symlinks don't work
            // Use .mjs (ESM) version for compatibility with Vite/Rollup
            "keycast-login": path.resolve(__dirname, "../keycast-login/dist/index.mjs"),
        },
    },
    optimizeDeps: {
        include: ["nostr-tools", "nostr-tools/pure", "nostr-tools/nip19"],
    },
    server: {
        proxy: {
            '^/verify-email(?:\\?.*)?$': {
                target: 'http://localhost:3000',
                headers: { host: 'login.divine.video' }
            },
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
