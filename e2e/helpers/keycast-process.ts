import net from "node:net";
import path from "node:path";
import { spawn, ChildProcess } from "node:child_process";

const DEFAULT_DATABASE_URL = "postgres://postgres:password@localhost/keycast";
const DEFAULT_REDIS_URL = "redis://localhost:16379";

function isPortReachable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Port ${port} not reachable after ${timeoutMs}ms`));
          return;
        }
        setTimeout(tryConnect, 200);
      });
    };
    tryConnect();
  });
}

function waitForExit(processHandle: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (processHandle.exitCode !== null) {
    return Promise.resolve(true);
  }

  return new Promise((resolve) => {
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      processHandle.off("exit", onExit);
      resolve(false);
    }, timeoutMs);
    processHandle.once("exit", onExit);
  });
}

function defaultEnv(port: number): Record<string, string> {
  const workspaceRoot = path.resolve(__dirname, "..", "..");
  return {
    DATABASE_URL: process.env.DATABASE_URL || DEFAULT_DATABASE_URL,
    REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS_URL,
    MASTER_KEY_PATH: process.env.MASTER_KEY_PATH || `${workspaceRoot}/master.key`,
    SERVER_NSEC:
      process.env.SERVER_NSEC ||
      "0000000000000000000000000000000000000000000000000000000000000001",
    BUNKER_RELAYS: process.env.BUNKER_RELAYS || "ws://localhost:8080",
    ALLOWED_ORIGINS:
      process.env.ALLOWED_ORIGINS ||
      "http://localhost:3000,http://localhost:5173,http://localhost:5174",
    ALLOWED_TENANT_DOMAINS:
      process.env.ALLOWED_TENANT_DOMAINS ||
      "localhost,tenant-a.localhost,tenant-b.localhost",
    ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX:
      process.env.ATPROTO_OAUTH_JWT_PRIVATE_KEY_HEX ||
      "8f2a55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d078d",
    ATPROTO_OAUTH_PDS_DID:
      process.env.ATPROTO_OAUTH_PDS_DID || "did:web:pds.divine.test",
    APP_URL: process.env.APP_URL || `http://localhost:${port}`,
    BASE_URL: process.env.BASE_URL || `http://localhost:${port}`,
    ENABLE_DEV_EMAIL_INBOX: "true",
    NODE_ENV: "test",
    PORT: String(port),
  };
}

export async function startKeycastProcess(opts: {
  port: number;
  env?: Record<string, string>;
  timeoutMs?: number;
}): Promise<ChildProcess> {
  if (await isPortReachable(opts.port)) {
    throw new Error(`Port ${opts.port} is already in use before starting keycast`);
  }

  const workspaceRoot = path.resolve(__dirname, "..", "..");
  const binaryPath =
    process.env.KEYCAST_BINARY || path.join(workspaceRoot, "target", "debug", "keycast");

  const child = spawn(binaryPath, [], {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      ...defaultEnv(opts.port),
      ...(opts.env || {}),
    },
    stdio: "pipe",
  });

  const exitedBeforeReady = new Promise<never>((_, reject) => {
    child.once("exit", (code, signal) => {
      reject(
        new Error(
          `keycast exited before becoming ready (code=${String(code)}, signal=${String(signal)})`,
        ),
      );
    });
  });

  await Promise.race([waitForPort(opts.port, opts.timeoutMs ?? 30_000), exitedBeforeReady]);
  return child;
}

export async function stopKeycastProcess(
  processHandle: ChildProcess | null | undefined,
): Promise<void> {
  if (!processHandle || processHandle.exitCode !== null) {
    return;
  }

  processHandle.kill("SIGTERM");
  const exited = await waitForExit(processHandle, 2_000);
  if (!exited && processHandle.exitCode === null) {
    processHandle.kill("SIGKILL");
    await waitForExit(processHandle, 1_000);
  }
}
