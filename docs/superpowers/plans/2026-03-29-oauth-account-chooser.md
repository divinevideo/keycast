# OAuth Account Chooser Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add chooser-first account UX for third-party OAuth new-app flows and for the first-party `/login` page when a valid cookie session already exists, without introducing true multi-account session support.

**Architecture:** Keep the existing single-session cookie model and extend the current decision trees instead of introducing new auth state. Third-party OAuth stays centered in `api/src/api/http/oauth.rs` with one new chooser branch before consent for authenticated new-app flows; the first-party login page reuses `/api/oauth/auth-status` plus existing logout behavior to switch between chooser and form modes.

**Tech Stack:** Rust/Axum server-rendered OAuth pages, SvelteKit frontend, Playwright e2e tests, existing `/api/auth/logout` and `/api/oauth/auth-status` endpoints.

---

## Chunk 1: Third-Party OAuth Chooser

### Task 1: Lock the New-App Chooser Behavior in Playwright

**Files:**
- Modify: `e2e/tests/oauth.spec.ts`
- Test: `e2e/tests/oauth.spec.ts`

- [ ] **Step 1: Write the failing browser test for chooser-first new-app auth**

Add a new test near the existing consent-page tests that:

```ts
test("authenticated new app shows account chooser before consent", async ({ page, request, context }) => {
  const { email, cookie } = await setupUser(request);
  const sessionValue = cookie.replace("keycast_session=", "");
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

  await page.goto(`/api/oauth/authorize?client_id=e2e-chooser&redirect_uri=${encodeURIComponent(CALLBACK_URL)}&scope=policy:full`);

  await expect(page.locator("text=Continue as")).toBeVisible();
  await expect(page.locator(`text=${email}`)).toBeVisible();
  await expect(page.locator("text=Use a different account")).toBeVisible();
  await expect(page.locator(".btn_approve")).toHaveCount(0);
});
```

- [ ] **Step 2: Run the single test to verify it fails**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "authenticated new app shows account chooser before consent"
```

Expected: FAIL because `/api/oauth/authorize` currently renders the consent screen directly for authenticated new-app flows.

- [ ] **Step 3: Implement the minimal chooser branch in the OAuth GET handler**

Modify `api/src/api/http/oauth.rs` to:

```rust
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    // existing fields...
    pub screen: Option<String>,
}
```

and branch the authenticated/new-origin path roughly like:

```rust
let chooser_confirmed = params.screen.as_deref() == Some("consent");

if user_pubkey.is_some() && !chooser_confirmed && is_new_origin {
    return Ok(render_account_chooser_page(...).into_response());
}

if user_pubkey.is_some() {
    return Ok(render_consent_page(...).into_response());
}
```

Keep auto-approve checks for `authorization_handle` and active-origin repeat auth before this chooser branch.

- [ ] **Step 4: Run the single test to verify it passes**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "authenticated new app shows account chooser before consent"
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add e2e/tests/oauth.spec.ts api/src/api/http/oauth.rs
git commit -m "feat: show chooser for new oauth app sessions"
```

### Task 2: Wire Continue and Switch-Account Paths

**Files:**
- Modify: `api/src/api/http/oauth.rs`
- Modify: `e2e/tests/oauth.spec.ts`
- Test: `e2e/tests/oauth.spec.ts`

- [ ] **Step 1: Write failing tests for chooser actions**

Add two tests:

```ts
test("chooser continue renders consent for the same account", async ({ page, request, context }) => {
  // set session cookie, visit /api/oauth/authorize for a new app
  await page.locator("text=Continue as").click();
  await expect(page.locator("h1")).toContainText("Authorize");
  await expect(page.locator(".btn_approve")).toBeVisible();
});

test("chooser switch account clears session and shows login", async ({ page, request, context }) => {
  // set session cookie, visit chooser
  await page.locator("text=Use a different account").click();
  await expect(page.locator("h1")).toContainText("Sign in");
  await expect(page.locator("input#login_email")).toBeVisible();
});
```

- [ ] **Step 2: Run only the new chooser-action tests and verify they fail**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "chooser continue|chooser switch account"
```

Expected: FAIL because there is no chooser action wiring yet.

- [ ] **Step 3: Implement chooser actions with existing endpoints**

In `api/src/api/http/oauth.rs`, render chooser HTML/JS that:

```js
function continueAsCurrentAccount() {
  const url = new URL(window.location.href);
  url.searchParams.set("screen", "consent");
  window.location.href = url.toString();
}

async function useDifferentAccount() {
  await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
  const url = new URL(window.location.href);
  url.searchParams.delete("screen");
  window.location.href = url.toString();
}
```

Also update the consent page header to keep the chosen account explicit and retain a `Use a different account` secondary action there.

- [ ] **Step 4: Re-run the chooser-action tests**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "chooser continue|chooser switch account"
```

Expected: PASS

- [ ] **Step 5: Re-run repeat-origin regression coverage**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts -g "auto-approve repeat origin|no consent after logout and relogin"
```

Expected: PASS, proving the chooser change did not break the repeat-app fast path.

- [ ] **Step 6: Commit the slice**

```bash
git add e2e/tests/oauth.spec.ts api/src/api/http/oauth.rs
git commit -m "feat: add oauth chooser actions"
```

## Chunk 2: First-Party `/login` Chooser

### Task 3: Add Login-Page Chooser State

**Files:**
- Modify: `web/src/routes/login/+page.svelte`
- Modify: `web/src/lib/utils/auth.ts`
- Modify: `e2e/tests/auth.spec.ts`
- Test: `e2e/tests/auth.spec.ts`

- [ ] **Step 1: Write a failing Playwright page test for authenticated `/login`**

Add a new browser test in `e2e/tests/auth.spec.ts`:

```ts
test("login page shows chooser when session cookie exists", async ({ page, request, context }) => {
  const email = `e2e-login-chooser-${Date.now()}@test.local`;
  const password = "TestPass123!";
  const { cookie } = await registerAndVerify(request, email, password);
  const sessionValue = parseCookieValue(cookie);
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

  await page.goto("/login");

  await expect(page.locator("text=Continue as")).toBeVisible();
  await expect(page.locator(`text=${email}`)).toBeVisible();
  await expect(page.locator("text=Use a different account")).toBeVisible();
  await expect(page.locator("input#email")).toHaveCount(0);
});
```

- [ ] **Step 2: Run the single `/login` chooser test to verify it fails**

Run:

```bash
cd e2e && npm test -- tests/auth.spec.ts -g "login page shows chooser when session cookie exists"
```

Expected: FAIL because `/login` currently renders the normal form regardless of auth status.

- [ ] **Step 3: Implement chooser mode in the login page**

Update `web/src/routes/login/+page.svelte` to:

```ts
let hasExistingSession = $state(false);
let currentSessionEmail = $state("");
let checkingSession = $state(true);

onMount(async () => {
  hasExtension = typeof window !== "undefined" && !!window.nostr;

  try {
    const status = await api.get<{ authenticated: boolean; email?: string; pubkey?: string }>("/oauth/auth-status");
    hasExistingSession = !!status.authenticated;
    currentSessionEmail = status.email || status.pubkey || "";
  } finally {
    checkingSession = false;
  }
});
```

Render chooser UI instead of the form when `hasExistingSession` is true.

- [ ] **Step 4: Add a lower-level logout helper that does not force navigation**

Refactor `web/src/lib/utils/auth.ts` so the login page can clear the cookie without the global `goto("/")` side effect. One safe shape is:

```ts
export async function clearSessionCookie() {
  await fetch(`${getViteDomain()}/api/auth/logout`, {
    method: "POST",
    credentials: "include",
  });
  setCurrentUser(null);
}

export async function signout() {
  await clearSessionCookie();
  toast.success("Signed out");
  goto("/");
}
```

Use `clearSessionCookie()` from `/login` when the user picks `Use a different account`.

- [ ] **Step 5: Re-run the single `/login` chooser test**

Run:

```bash
cd e2e && npm test -- tests/auth.spec.ts -g "login page shows chooser when session cookie exists"
```

Expected: PASS

- [ ] **Step 6: Commit the slice**

```bash
git add web/src/routes/login/+page.svelte web/src/lib/utils/auth.ts e2e/tests/auth.spec.ts
git commit -m "feat: add chooser for existing login sessions"
```

### Task 4: Verify Continue and Switch-Account Behavior on `/login`

**Files:**
- Modify: `e2e/tests/auth.spec.ts`
- Modify: `web/src/routes/login/+page.svelte`
- Test: `e2e/tests/auth.spec.ts`

- [ ] **Step 1: Write failing tests for chooser actions on `/login`**

Add:

```ts
test("login chooser continue uses existing session", async ({ page, request, context }) => {
  // seed session cookie, visit /login?redirect=/teams
  await page.locator("text=Continue as").click();
  await page.waitForURL(/\/teams|\/$/);
});

test("login chooser switch account reveals login form", async ({ page, request, context }) => {
  // seed session cookie, visit /login
  await page.locator("text=Use a different account").click();
  await expect(page.locator("input#email")).toBeVisible();
  await expect(page.locator("input#password")).toBeVisible();
});
```

- [ ] **Step 2: Run the two `/login` chooser-action tests and verify they fail**

Run:

```bash
cd e2e && npm test -- tests/auth.spec.ts -g "login chooser continue|login chooser switch account"
```

Expected: FAIL

- [ ] **Step 3: Implement chooser actions in the page**

In `web/src/routes/login/+page.svelte`, add:

```ts
async function continueWithCurrentSession() {
  const redirect = $page.url.searchParams.get("redirect");
  goto(redirect && redirect.startsWith("/") ? redirect : "/");
}

async function switchAccount() {
  await clearSessionCookie();
  hasExistingSession = false;
  currentSessionEmail = "";
}
```

If logout fails, show a toast and keep chooser mode visible.

- [ ] **Step 4: Re-run the `/login` chooser-action tests**

Run:

```bash
cd e2e && npm test -- tests/auth.spec.ts -g "login chooser continue|login chooser switch account"
```

Expected: PASS

- [ ] **Step 5: Commit the slice**

```bash
git add web/src/routes/login/+page.svelte e2e/tests/auth.spec.ts
git commit -m "feat: wire login chooser actions"
```

## Chunk 3: Full Verification and Cleanup

### Task 5: Run Focused Regression and Type Checks

**Files:**
- Verify: `api/src/api/http/oauth.rs`
- Verify: `web/src/routes/login/+page.svelte`
- Verify: `web/src/lib/utils/auth.ts`
- Verify: `e2e/tests/oauth.spec.ts`
- Verify: `e2e/tests/auth.spec.ts`

- [ ] **Step 1: Run the complete OAuth spec file**

Run:

```bash
cd e2e && npm test -- tests/oauth.spec.ts
```

Expected: PASS

- [ ] **Step 2: Run the complete auth spec file**

Run:

```bash
cd e2e && npm test -- tests/auth.spec.ts
```

Expected: PASS

- [ ] **Step 3: Run the web type and Svelte checks**

Run:

```bash
cd web && npm run check
```

Expected: PASS

- [ ] **Step 4: Inspect the final diff for scope drift**

Run:

```bash
git diff --stat HEAD~4..HEAD
git diff -- api/src/api/http/oauth.rs web/src/routes/login/+page.svelte web/src/lib/utils/auth.ts e2e/tests/oauth.spec.ts e2e/tests/auth.spec.ts
```

Expected: only chooser-related server HTML, login-page chooser state, logout-helper reuse, and focused test additions.

- [ ] **Step 5: Commit the verification pass if cleanup changes were needed**

```bash
git add api/src/api/http/oauth.rs web/src/routes/login/+page.svelte web/src/lib/utils/auth.ts e2e/tests/oauth.spec.ts e2e/tests/auth.spec.ts
git commit -m "test: verify oauth chooser regressions"
```
