import { execSync } from "node:child_process";

const CONTAINER_NAME = "keycast-e2e-relay";

export default async function globalTeardown() {
  try {
    execSync(`docker stop ${CONTAINER_NAME}`, { stdio: "ignore" });
  } catch {
    // Container already stopped
  }
}
