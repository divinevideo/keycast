import { execSync } from "node:child_process";
import net from "node:net";

const CONTAINER_NAME = "keycast-e2e-relay";
const PORT = 8080;
const TIMEOUT_MS = 10_000;

function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    function tryConnect() {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Port ${port} not reachable after ${timeoutMs}ms`));
        } else {
          setTimeout(tryConnect, 200);
        }
      });
    }
    tryConnect();
  });
}

export default async function globalSetup() {
  // Stop any leftover container from a previous run
  try {
    execSync(`docker stop ${CONTAINER_NAME}`, { stdio: "ignore" });
  } catch {
    // Container didn't exist
  }

  execSync(
    `docker run --rm -d --name ${CONTAINER_NAME} -p ${PORT}:${PORT} -e IDLE_TIMEOUT=0 ghcr.io/verse-pbc/relay_builder:latest`,
    { stdio: "inherit" },
  );

  await waitForPort(PORT, TIMEOUT_MS);
}
