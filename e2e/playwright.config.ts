import { defineConfig } from "@playwright/test";
import dns from "node:dns";

// Force IPv4 for Node.js request context (API tests)
// Prevents "localhost" from resolving to ::1 when server binds 0.0.0.0
dns.setDefaultResultOrder("ipv4first");

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 2 : 0,
  reporter: "html",
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  use: {
    baseURL: process.env.API_URL || "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    extraHTTPHeaders: {
      Origin: process.env.API_URL || "http://localhost:3000",
    },
    launchOptions: {
      // Force Chromium to resolve localhost as 127.0.0.1
      args: ["--host-resolver-rules=MAP localhost 127.0.0.1"],
    },
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
  webServer: {
    command: "npx serve fixtures -l 3456 --no-clipboard",
    port: 3456,
    reuseExistingServer: true,
  },
});
