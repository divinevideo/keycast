import { test, expect } from "@playwright/test";
import { parseCookieValue, registerAndVerify } from "../helpers/auth";

test.describe("NIP-05 profile badge", () => {
  test("dashboard shows verified NIP-05 identifier", async ({
    page,
    request,
    context,
  }) => {
    const email = `e2e-nip05-${Date.now()}@test.local`;
    const password = "TestPass123!";
    const { cookie } = await registerAndVerify(request, email, password);
    const sessionValue = parseCookieValue(cookie);
    const sessionCookie = `keycast_session=${sessionValue}`;

    const updateRes = await request.post("/api/user/profile", {
      headers: { Cookie: sessionCookie },
      data: { username: "Alice.Name_123" },
    });
    expect(updateRes.status()).toBe(200);

    const profileRes = await request.get("/api/user/profile", {
      headers: { Cookie: sessionCookie },
    });
    expect(profileRes.status()).toBe(200);
    const profile = await profileRes.json();
    expect(profile.username).toBe("alice.name_123");
    expect(profile.nip05).toBe("alice.name_123@divine.video");

    const baseURL = process.env.API_URL || "http://localhost:3000";
    const url = new URL(baseURL);
    await context.addCookies([
      {
        name: "keycast_session",
        value: sessionValue,
        domain: url.hostname,
        path: "/",
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);

    await page.goto("/");
    await expect(page.locator("text=NIP-05 Verified")).toBeVisible();
    await expect(page.locator("text=alice.name_123@divine.video")).toBeVisible();
  });
});
