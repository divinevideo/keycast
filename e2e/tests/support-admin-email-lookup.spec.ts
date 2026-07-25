import { type Page, type TestInfo, expect, test } from "@playwright/test";
import { parseCookieValue, registerAndVerify } from "../helpers/auth";
import { withDb } from "../helpers/db";
import { addSupportAdmin, clearSupportAdmins } from "../helpers/redis";

const PASSWORD = "TestPass123!";
const LITERAL_PUBLISH_EMAIL = "socialpublishcommunity@gmail.com";
const TYPO_NEAR_EMAIL = "socialpulishllc@gmail.com";
const ACCOUNT_EMAILS = [
  LITERAL_PUBLISH_EMAIL,
  TYPO_NEAR_EMAIL,
  "socialpanda@gmail.com",
  "socialpirate@gmail.com",
];

async function deleteTestAccounts(emails: string[]): Promise<void> {
  await withDb(async (db) => {
    await db.query("DELETE FROM users WHERE email = ANY($1::text[])", [emails]);
  });
}

async function captureLookupState(
  page: Page,
  testInfo: TestInfo,
  name: string,
): Promise<void> {
  const screenshot = await page.screenshot({ fullPage: true });
  await testInfo.attach(name, { body: screenshot, contentType: "image/png" });
}

async function search(page: Page, query: string): Promise<void> {
  await page.locator(".search-input").fill(query);
  await page.locator(".btn-search").click();
  await expect(page.locator(".btn-search")).toHaveText("Search");
}

test.describe("Support admin email lookup UI", () => {
  let supportEmail = "";

  test.beforeEach(async () => {
    await deleteTestAccounts(ACCOUNT_EMAILS);
  });

  test.afterEach(async () => {
    await clearSupportAdmins();
    await deleteTestAccounts([...ACCOUNT_EMAILS, supportEmail].filter(Boolean));
  });

  test("makes contains, typo, and exact email matches legible", async (
    { page, request },
    testInfo,
  ) => {
    test.setTimeout(120_000);

    for (const email of ACCOUNT_EMAILS) {
      await registerAndVerify(request, email, PASSWORD);
    }

    supportEmail = `e2e-lookup-support-${Date.now()}@test.local`;
    const { cookie } = await registerAndVerify(request, supportEmail, PASSWORD);
    const accountResponse = await request.get("/api/user/account", {
      headers: {
        Cookie: `keycast_session=${parseCookieValue(cookie)}`,
      },
    });
    expect(accountResponse.ok()).toBe(true);
    const supportAccount = await accountResponse.json();
    await addSupportAdmin(supportAccount.public_key);

    await page.goto("/login?redirect=/support-admin");
    await page.locator('input[type="email"]').fill(supportEmail);
    await page.locator('input[type="password"]').fill(PASSWORD);
    await page.locator('button[type="submit"]').click();
    await page.waitForURL("**/support-admin");
    await expect(page.getByText("Support Admin", { exact: true })).toBeVisible();

    await search(page, "socialp");
    await expect(page.locator(".user-list-item")).toHaveCount(4);
    await expect(page.locator(".user-list-item .email-match")).toHaveCount(4);
    await expect(page.locator(".user-list-item .email-match")).toHaveText([
      "socialp",
      "socialp",
      "socialp",
      "socialp",
    ]);
    await captureLookupState(page, testInfo, "support-admin-email-contains");

    await search(page, "publish");
    const mixedRows = page.locator(".user-list-item");
    await expect(mixedRows).toHaveCount(2);
    await expect(mixedRows.locator(".list-name")).toHaveText([
      LITERAL_PUBLISH_EMAIL,
      TYPO_NEAR_EMAIL,
    ]);
    await expect(mixedRows.locator(".match-kind-badge")).toHaveText([
      "Partial match",
      "Possible typo",
    ]);
    await expect(mixedRows.nth(0).locator(".email-match")).toHaveText("publish");
    await expect(mixedRows.nth(1).getByRole("note")).toContainText(
      "This email is close to your search, not a literal match.",
    );
    await expect(page.getByRole("heading", { name: "Did you mean?" })).toHaveCount(0);
    await captureLookupState(page, testInfo, "support-admin-email-mixed-match-tiers");

    await search(page, LITERAL_PUBLISH_EMAIL);
    await expect(page.locator(".user-list-item")).toHaveCount(1);
    await expect(page.locator(".user-list-item .list-name")).toHaveText(
      LITERAL_PUBLISH_EMAIL,
    );
    await expect(page.locator(".user-card")).toBeVisible();
    await expect(page.locator(".match-kind-badge")).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Did you mean?" })).toHaveCount(0);

    await search(page, "socialpublishllc@gmail.com");
    await expect(page.getByRole("heading", { name: "Did you mean?" })).toBeVisible();
    await expect(page.getByRole("note")).toContainText(
      "These are different addresses — confirm identity before acting.",
    );
    await expect(page.locator(".user-list-item")).toHaveCount(1);
    await expect(page.locator(".user-list-item .list-name")).toHaveText(
      TYPO_NEAR_EMAIL,
    );
    await expect(page.locator(".suggestion-distance")).toHaveText(
      "1 letter off · missing 'b'",
    );
    await expect(
      page.getByRole("img", { name: "socialpublishllc@gmail.com" }),
    ).toBeVisible();
    await expect(
      page.getByRole("img", { name: TYPO_NEAR_EMAIL }),
    ).toBeVisible();
    await expect(page.locator(".diff-line").nth(0).locator(".diff-character")).toHaveText(
      "b",
    );
    await expect(page.locator(".diff-line").nth(1).locator(".diff-character")).toHaveText(
      "∅",
    );
    await captureLookupState(page, testInfo, "support-admin-email-suggestion");

    await search(page, TYPO_NEAR_EMAIL);
    await expect(page.locator(".user-list-item")).toHaveCount(1);
    await expect(page.locator(".user-card")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Did you mean?" })).toHaveCount(0);
    await expect(page.locator(".email-match")).toHaveCount(0);
  });
});
