<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { toast } from "svelte-hot-french-toast";
  import { AtprotoSettingsModel } from "$lib/atproto_status.svelte";

  const settings = new AtprotoSettingsModel();

  let usernameInput = $state("");

  $effect(() => {
    if (settings.username && settings.username !== usernameInput && !settings.isBusy) {
      usernameInput = settings.username;
    }
  });

  onMount(async () => {
    try {
      await settings.load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to load Bluesky settings");
    }
  });

  onDestroy(() => {
    settings.dispose();
  });

  async function handleClaimUsername() {
    try {
      await settings.claimUsername(usernameInput);
      toast.success("Username claimed");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to claim username");
    }
  }

  async function handleEnable() {
    try {
      await settings.enable();
      toast.success("Bluesky provisioning started");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to enable Bluesky");
    }
  }

  async function handleDisable() {
    try {
      await settings.disable();
      toast.success("Bluesky cross-posting disabled");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to disable Bluesky");
    }
  }
</script>

<div class="section bluesky-section" data-testid="bluesky-settings-card">
  <div class="section-header">
    <h2>Bluesky Account</h2>
    <p>
      Claim your Divine handle, provision your Bluesky identity, and control whether future
      cross-posts are allowed.
    </p>
  </div>

  {#if settings.isLoading && !settings.status && !settings.profile}
    <div class="state-panel">
      <span class="state-badge neutral">Loading</span>
      <p>Checking your claimed username and Bluesky lifecycle.</p>
    </div>
  {:else}
    {#if settings.requestError}
      <div class="notice error" role="status">
        <strong>Request issue</strong>
        <p>{settings.requestError}</p>
      </div>
    {/if}

    {#if settings.uiState === "claim_username"}
      <div class="state-panel">
        <span class="state-badge neutral">No username claimed</span>
        <p>Claim a <strong>username.divine.video</strong> handle before you enable Bluesky.</p>

        <div class="claim-row">
          <label class="form-group" for="atproto-username">
            <span>Username</span>
            <div class="username-field">
              <input
                id="atproto-username"
                type="text"
                bind:value={usernameInput}
                autocomplete="off"
                autocapitalize="none"
                spellcheck="false"
                placeholder="yourname"
                disabled={settings.isClaiming}
              />
              <span class="domain-suffix">.divine.video</span>
            </div>
          </label>

          <button
            class="btn-primary"
            onclick={handleClaimUsername}
            disabled={settings.isClaiming || !usernameInput.trim()}
          >
            {settings.isClaiming ? "Claiming..." : "Claim username"}
          </button>
        </div>

        <p class="helper-copy">Use letters, numbers, and hyphens only.</p>
      </div>
    {:else if settings.uiState === "ready_to_enable"}
      <div class="state-panel">
        <span class="state-badge neutral">Bluesky disabled</span>
        <div class="handle-chip">{settings.handle}</div>
        <p>
          Enabling will provision a DID, publish your handle, and turn on future cross-posting once
          the lifecycle reaches ready.
        </p>
        <button class="btn-primary" onclick={handleEnable} disabled={settings.isEnabling}>
          {settings.isEnabling ? "Starting..." : "Enable Bluesky account"}
        </button>
      </div>
    {:else if settings.uiState === "pending"}
      <div class="state-panel">
        <span class="state-badge pending">Provisioning</span>
        <div class="handle-chip">@{settings.handle}</div>
        <p>Provisioning in progress. This page will keep checking until the lifecycle settles.</p>
      </div>
    {:else if settings.uiState === "ready"}
      <div class="state-panel">
        <span class="state-badge ready">Ready</span>
        <div class="handle-chip">@{settings.handle}</div>
        <dl class="details-grid">
          <div>
            <dt>DID</dt>
            <dd>{settings.did}</dd>
          </div>
        </dl>
        <p>Public handle resolution and future cross-posting are active.</p>
        <button class="btn-secondary" onclick={handleDisable} disabled={settings.isDisabling}>
          {settings.isDisabling ? "Disabling..." : "Disable Bluesky account"}
        </button>
      </div>
    {:else if settings.uiState === "failed"}
      <div class="state-panel">
        <span class="state-badge failed">Failed</span>
        <div class="handle-chip">{settings.handle}</div>
        <p>The last provisioning attempt failed. You can retry with the same claimed username.</p>
        {#if settings.provisioningError}
          <div class="notice error" role="status">
            <strong>Last error</strong>
            <p>{settings.provisioningError}</p>
          </div>
        {/if}
        <button class="btn-primary" onclick={handleEnable} disabled={settings.isEnabling}>
          {settings.isEnabling ? "Retrying..." : "Enable Bluesky account"}
        </button>
      </div>
    {:else if settings.uiState === "disabled"}
      <div class="state-panel">
        <span class="state-badge disabled">Disabled</span>
        <div class="handle-chip">{settings.handle}</div>
        <p>Public DID resolution and future cross-posting are disabled for this handle.</p>
        <button class="btn-primary" onclick={handleEnable} disabled={settings.isEnabling}>
          {settings.isEnabling ? "Starting..." : "Enable Bluesky account"}
        </button>
      </div>
    {/if}
  {/if}
</div>

<style>
  .bluesky-section {
    border-color: color-mix(in srgb, var(--color-divine-green) 25%, var(--color-divine-border));
  }

  .state-panel {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    padding: 1.25rem;
    border-radius: 10px;
    background:
      linear-gradient(135deg, color-mix(in srgb, var(--color-divine-green) 8%, transparent), transparent 45%),
      var(--color-divine-bg);
    border: 1px solid color-mix(in srgb, var(--color-divine-green) 18%, var(--color-divine-border));
  }

  .state-panel p {
    margin: 0;
    color: var(--color-divine-text-secondary);
    font-size: 0.92rem;
    line-height: 1.5;
  }

  .state-badge {
    display: inline-flex;
    align-self: flex-start;
    padding: 0.35rem 0.7rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .state-badge.neutral {
    background: var(--color-divine-muted);
    color: var(--color-divine-text);
  }

  .state-badge.pending {
    background: color-mix(in srgb, var(--color-divine-warning) 15%, transparent);
    color: var(--color-divine-warning);
  }

  .state-badge.ready {
    background: color-mix(in srgb, var(--color-divine-green) 15%, transparent);
    color: var(--color-divine-green);
  }

  .state-badge.failed {
    background: color-mix(in srgb, var(--color-divine-error) 14%, transparent);
    color: var(--color-divine-error);
  }

  .state-badge.disabled {
    background: color-mix(in srgb, var(--color-divine-text-secondary) 14%, transparent);
    color: var(--color-divine-text-secondary);
  }

  .handle-chip {
    width: fit-content;
    max-width: 100%;
    padding: 0.55rem 0.85rem;
    border-radius: 9999px;
    background: color-mix(in srgb, var(--color-divine-bg) 70%, var(--color-divine-surface));
    border: 1px solid var(--color-divine-border);
    color: var(--color-divine-text);
    font-family: var(--font-mono);
    font-size: 0.88rem;
    overflow-wrap: anywhere;
  }

  .claim-row {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }

  .username-field {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    background: var(--color-divine-surface);
    border: 1px solid var(--color-divine-border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .username-field input {
    border: 0;
    border-radius: 0;
    background: transparent;
  }

  .username-field input:focus {
    border-color: transparent;
  }

  .domain-suffix {
    padding: 0 0.85rem 0 0.3rem;
    color: var(--color-divine-text-secondary);
    font-size: 0.88rem;
    white-space: nowrap;
  }

  .helper-copy {
    font-size: 0.8rem;
  }

  .details-grid {
    display: grid;
    gap: 0.75rem;
    margin: 0;
  }

  .details-grid dt {
    margin-bottom: 0.2rem;
    color: var(--color-divine-text-secondary);
    font-size: 0.76rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .details-grid dd {
    margin: 0;
    color: var(--color-divine-text);
    font-family: var(--font-mono);
    font-size: 0.88rem;
    overflow-wrap: anywhere;
  }

  .notice {
    padding: 0.95rem 1rem;
    border-radius: 10px;
    border: 1px solid transparent;
  }

  .notice strong {
    display: block;
    margin-bottom: 0.25rem;
    font-size: 0.82rem;
  }

  .notice p {
    margin: 0;
  }

  .notice.error {
    background: color-mix(in srgb, var(--color-divine-error) 10%, var(--color-divine-bg));
    border-color: color-mix(in srgb, var(--color-divine-error) 30%, transparent);
  }

  .notice.error strong,
  .notice.error p {
    color: var(--color-divine-error);
  }

  @media (min-width: 700px) {
    .claim-row {
      align-items: end;
      grid-template-columns: minmax(0, 1fr) auto;
      display: grid;
    }
  }
</style>
