import type { APIRequestContext } from "@playwright/test";

interface DeliveredTokenOptions {
  email: string;
  pathname: "/verify-email" | "/api/claim/confirm";
  baseUrl?: string;
  attempts?: number;
  pause?: (milliseconds: number) => Promise<void>;
  beforeRead?: () => Promise<void>;
}

/** Read a bearer only from the development sender's actual captured delivery. */
export async function getDeliveredToken(
  request: APIRequestContext,
  options: DeliveredTokenOptions,
): Promise<string> {
  const route = options.baseUrl
    ? new URL("/api/dev/emails", options.baseUrl).toString()
    : "/api/dev/emails";
  const pause = options.pause ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  for (let attempt = 0; attempt < (options.attempts ?? 10); attempt++) {
    await options.beforeRead?.();
    let messages: unknown;
    try {
      const response = await request.get(route, {
        headers: options.baseUrl ? { Origin: options.baseUrl } : undefined,
        timeout: 15000,
        maxRedirects: 0,
      });
      if (!response.ok()) throw new Error("email_inbox_unavailable");
      messages = await response.json();
    } catch {
      // HTTP diagnostics may include the complete inbox, including other test credentials.
      throw new Error("email_inbox_unavailable: enable ENABLE_DEV_EMAIL_INBOX=true on the owned non-production test server");
    }
    if (!Array.isArray(messages)) throw new Error("email_inbox_invalid_response");
    for (const message of [...messages].reverse()) {
      if (message?.to !== options.email || typeof message.verification_url !== "string") continue;
      let url: URL;
      try { url = new URL(message.verification_url); } catch { continue; }
      if (url.pathname !== options.pathname) continue;
      const tokens = url.searchParams.getAll("token");
      if (tokens.length === 1 && tokens[0]) return tokens[0];
    }
    if (attempt + 1 < (options.attempts ?? 10)) await pause(300);
  }
  throw new Error("email_delivery_token_timeout");
}

export function getVerificationToken(request: APIRequestContext, email: string): Promise<string> {
  return getDeliveredToken(request, { email, pathname: "/verify-email" });
}
