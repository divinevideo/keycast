import { KeycastApi } from "$lib/keycast_api.svelte";

export type AtprotoLifecycleState = "pending" | "ready" | "failed" | "disabled" | null;
export type AtprotoUiState =
  | "claim_username"
  | "ready_to_enable"
  | "pending"
  | "ready"
  | "failed"
  | "disabled";

type ProfileResponse = {
  username?: string | null;
};

type AtprotoStatusResponse = {
  enabled: boolean;
  state?: AtprotoLifecycleState;
  did?: string | null;
  error?: string | null;
  username?: string | null;
};

function normalizeUsername(username: string | null | undefined): string | null {
  const trimmed = username?.trim().toLowerCase() ?? "";
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeStatusResponse(
  status: AtprotoStatusResponse,
): Required<Pick<AtprotoStatusResponse, "enabled">> &
  Required<Pick<AtprotoStatusResponse, "state" | "did" | "error" | "username">> {
  return {
    enabled: status.enabled,
    state: status.state ?? null,
    did: status.did ?? null,
    error: status.error ?? null,
    username: normalizeUsername(status.username),
  };
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Something went wrong. Please try again.";
}

export class AtprotoSettingsModel {
  private readonly api: KeycastApi;
  private readonly pollIntervalMs: number;
  private pollTimeout: number | null = null;
  private disposed = false;

  profile = $state<{ username: string | null } | null>(null);
  status = $state<ReturnType<typeof normalizeStatusResponse> | null>(null);
  isLoading = $state(false);
  isClaiming = $state(false);
  isEnabling = $state(false);
  isDisabling = $state(false);
  requestError = $state<string | null>(null);

  constructor(api = new KeycastApi(), pollIntervalMs = 2_000) {
    this.api = api;
    this.pollIntervalMs = pollIntervalMs;
  }

  get username(): string | null {
    return this.status?.username ?? this.profile?.username ?? null;
  }

  get handle(): string | null {
    return this.username ? `${this.username}.divine.video` : null;
  }

  get did(): string | null {
    return this.status?.did ?? null;
  }

  get provisioningError(): string | null {
    return this.status?.error ?? null;
  }

  get isBusy(): boolean {
    return (
      this.isLoading || this.isClaiming || this.isEnabling || this.isDisabling
    );
  }

  get uiState(): AtprotoUiState {
    const username = this.username;

    if (!username) {
      return "claim_username";
    }

    if (!this.status) {
      return "ready_to_enable";
    }

    if (this.status.enabled && this.status.state === "pending") {
      return "pending";
    }

    if (this.status.enabled && this.status.state === "ready") {
      return "ready";
    }

    // A failed enable rolls the opt-in back to `enabled: false`, so the failure
    // is reported by the state alone. Requiring `enabled` here would drop the
    // "last attempt failed" explanation and show the plain enable card instead.
    if (this.status.state === "failed") {
      return "failed";
    }

    if (!this.status.enabled && this.status.state === "disabled") {
      return "disabled";
    }

    return "ready_to_enable";
  }

  async load(): Promise<void> {
    this.requestError = null;
    this.isLoading = true;

    try {
      await Promise.all([this.refreshProfile(), this.refreshStatus()]);
    } catch (error) {
      this.requestError = getErrorMessage(error);
      throw error;
    } finally {
      this.isLoading = false;
      this.syncPolling();
    }
  }

  async claimUsername(username: string): Promise<void> {
    const claimedUsername = normalizeUsername(username);

    if (!claimedUsername) {
      throw new Error("Username is required");
    }

    this.requestError = null;
    this.isClaiming = true;

    try {
      await this.api.post("/user/profile", { username: claimedUsername });
      await Promise.all([this.refreshProfile(), this.refreshStatus()]);
    } catch (error) {
      this.requestError = getErrorMessage(error);
      throw error;
    } finally {
      this.isClaiming = false;
      this.syncPolling();
    }
  }

  async enable(): Promise<void> {
    const username = this.username;

    if (!username) {
      throw new Error("Claim a username before enabling Bluesky");
    }

    this.requestError = null;
    this.isEnabling = true;

    try {
      const response = await this.api.post<AtprotoStatusResponse>(
        "/user/atproto/enable",
        { username },
      );

      if (!this.disposed) {
        this.status = normalizeStatusResponse(response);
      }
    } catch (error) {
      this.requestError = getErrorMessage(error);
      await this.refreshStatusAfterFailure();
      throw error;
    } finally {
      this.isEnabling = false;
      this.syncPolling();
    }
  }

  async disable(): Promise<void> {
    this.requestError = null;
    this.isDisabling = true;

    try {
      const response = await this.api.post<AtprotoStatusResponse>(
        "/user/atproto/disable",
      );

      if (!this.disposed) {
        this.status = normalizeStatusResponse(response);
      }
    } catch (error) {
      this.requestError = getErrorMessage(error);
      await this.refreshStatusAfterFailure();
      throw error;
    } finally {
      this.isDisabling = false;
      this.syncPolling();
    }
  }

  dispose(): void {
    this.disposed = true;
    this.clearPolling();
  }

  private async refreshProfile(): Promise<void> {
    const response = await this.api.get<ProfileResponse>("/user/profile");

    if (this.disposed) {
      return;
    }

    this.profile = {
      username: normalizeUsername(response.username),
    };
  }

  private async refreshStatus(): Promise<void> {
    const response = await this.api.get<AtprotoStatusResponse>(
      "/user/atproto/status",
    );

    if (this.disposed) {
      return;
    }

    this.status = normalizeStatusResponse(response);
  }

  private async refreshStatusAfterFailure(): Promise<void> {
    try {
      await this.refreshStatus();
    } catch {
      // Preserve the original request error when status refresh also fails.
    }
  }

  private syncPolling(): void {
    this.clearPolling();

    if (this.disposed || this.uiState !== "pending" || typeof window === "undefined") {
      return;
    }

    this.pollTimeout = window.setTimeout(async () => {
      try {
        await this.refreshStatus();
      } catch (error) {
        this.requestError = getErrorMessage(error);
      } finally {
        this.syncPolling();
      }
    }, this.pollIntervalMs);
  }

  private clearPolling(): void {
    if (this.pollTimeout !== null) {
      clearTimeout(this.pollTimeout);
      this.pollTimeout = null;
    }
  }
}
