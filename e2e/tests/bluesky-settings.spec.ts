import { expect, test } from "@playwright/test";

type ProfileResponse = {
  username: string | null;
  name: null;
  about: null;
  picture: null;
  banner: null;
  nip05: null;
  website: null;
  lud16: null;
};

type AtprotoStatusResponse = {
  enabled: boolean;
  state: "pending" | "ready" | "failed" | "disabled" | null;
  did: string | null;
  error: string | null;
  username: string | null;
};

const MOCK_PUBKEY =
  "25fa07621969c92191feb4433fca94fdb500f2b445fd4f017c0a332ceecbf813";

test.describe("Bluesky settings", () => {
  test("managed user can claim a username and enable Bluesky from security settings", async ({
    page,
  }) => {
    test.setTimeout(60_000);

    await page.addInitScript(() => {
      window.localStorage.setItem("keycast_auth_method", "cookie");
    });

    let profile: ProfileResponse = {
      username: null,
      name: null,
      about: null,
      picture: null,
      banner: null,
      nip05: null,
      website: null,
      lud16: null,
    };

    let atproto: AtprotoStatusResponse = {
      enabled: false,
      state: null,
      did: null,
      error: null,
      username: null,
    };

    let statusPollCount = 0;

    await page.route("**/api/oauth/auth-status", async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          authenticated: true,
          pubkey: MOCK_PUBKEY,
          email: "bluesky-settings@test.local",
          email_verified: true,
        },
      });
    });

    await page.route("**/api/user/account", async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          email: "bluesky-settings@test.local",
          email_verified: true,
          public_key: MOCK_PUBKEY,
        },
      });
    });

    await page.route("**/api/user/profile", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({ status: 200, json: profile });
        return;
      }

      if (route.request().method() === "POST") {
        const body = route.request().postDataJSON() as { username?: string };
        const claimedUsername = body.username?.trim() ?? null;
        profile = { ...profile, username: claimedUsername };
        atproto = { ...atproto, username: claimedUsername };

        await route.fulfill({
          status: 200,
          json: {
            success: true,
            username: claimedUsername,
          },
        });
        return;
      }

      await route.fallback();
    });

    await page.route("**/api/user/atproto/status", async (route) => {
      if (atproto.enabled && atproto.state === "pending") {
        statusPollCount += 1;
        if (statusPollCount >= 2) {
          atproto = {
            ...atproto,
            state: "ready",
            did: "did:plc:e2eblueskysettings",
            error: null,
          };
        }
      }

      await route.fulfill({ status: 200, json: atproto });
    });

    await page.route("**/api/user/atproto/enable", async (route) => {
      atproto = {
        enabled: true,
        state: "pending",
        did: null,
        error: null,
        username: profile.username,
      };
      statusPollCount = 0;

      await route.fulfill({ status: 202, json: atproto });
    });

    await page.goto("/settings/security");

    await expect(
      page.getByRole("heading", { name: "Bluesky Account" }),
    ).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();

    await page.getByLabel("Username").fill("skybuilder");
    await page.getByRole("button", { name: "Claim username" }).click();

    await expect(page.getByText("skybuilder.divine.video")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Enable Bluesky account" }),
    ).toBeVisible();

    await page.getByRole("button", { name: "Enable Bluesky account" }).click();

    await expect(page.getByText("Provisioning in progress")).toBeVisible();
    await expect(page.getByText("@skybuilder.divine.video")).toBeVisible();
    await expect(
      page.getByText("did:plc:e2eblueskysettings"),
    ).toBeVisible();
  });

  test("failed and disabled lifecycle states keep retry and re-enable controls visible", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      window.localStorage.setItem("keycast_auth_method", "cookie");
    });

    let profile: ProfileResponse = {
      username: "skybuilder",
      name: null,
      about: null,
      picture: null,
      banner: null,
      nip05: null,
      website: null,
      lud16: null,
    };

    // The shape a failed enable leaves behind: the opt-in is rolled back, so
    // the failure is carried by the state and the error alone.
    let atproto: AtprotoStatusResponse = {
      enabled: false,
      state: "failed",
      did: null,
      error: "provisioning service returned 502 Bad Gateway: gateway unavailable",
      username: "skybuilder",
    };

    await page.route("**/api/oauth/auth-status", async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          authenticated: true,
          pubkey: MOCK_PUBKEY,
          email: "bluesky-settings@test.local",
          email_verified: true,
        },
      });
    });

    await page.route("**/api/user/account", async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          email: "bluesky-settings@test.local",
          email_verified: true,
          public_key: MOCK_PUBKEY,
        },
      });
    });

    await page.route("**/api/user/profile", async (route) => {
      await route.fulfill({ status: 200, json: profile });
    });

    await page.route("**/api/user/atproto/status", async (route) => {
      await route.fulfill({ status: 200, json: atproto });
    });

    await page.goto("/settings/security");

    await expect(page.getByText("Last error")).toBeVisible();
    await expect(
      page.getByText("gateway unavailable"),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Enable Bluesky account" }),
    ).toBeVisible();

    atproto = {
      enabled: false,
      state: "disabled",
      did: null,
      error: null,
      username: "skybuilder",
    };

    await page.reload();

    await expect(page.getByText("Public DID resolution and future cross-posting are disabled for this handle.")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Enable Bluesky account" }),
    ).toBeVisible();
  });
});
