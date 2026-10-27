import { defineConfig } from "@playwright/test";
import dns from "node:dns";

dns.setDefaultResultOrder("ipv4first");

// No development server/global hooks or default nightly helpers. The dedicated
// suite must write its strict aggregate to /tmp/challenge-image-summary.json.
export default defineConfig({
  testDir: "./challenge-image",
  testMatch: "challenge-image.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120000,
  globalTimeout: 600000,
  reporter: "line",
  outputDir: "/tmp/challenge-image-output",
  use: {
    baseURL: "http://localhost:3000",
    actionTimeout: 15000,
    navigationTimeout: 15000,
    trace: "off",
    video: "off",
    screenshot: "off",
    extraHTTPHeaders: { Origin: "http://localhost:3000" },
    launchOptions: {
      args: ["--host-resolver-rules=MAP localhost 127.0.0.1"],
    },
  },
  expect: { timeout: 15000 },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
