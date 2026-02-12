import net from "node:net";

const RELAY_PORT = 8080;
const API_PORT = 3000;
const TIMEOUT_MS = 30_000;

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
  // Verify the relay and API server are running (started by `bun run dev:e2e`)
  await waitForPort(RELAY_PORT, TIMEOUT_MS);
  await waitForPort(API_PORT, TIMEOUT_MS);
}
