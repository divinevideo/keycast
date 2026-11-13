# Email verification in E2E fixtures

The ordinary Playwright suite verifies email through actual deliveries captured by
the development sender. Its owned non-production API server must enable
`ENABLE_DEV_EMAIL_INBOX=true`. Helpers obtain raw verification and confirmation
tokens from those delivered links, never from database token columns.

The separate immutable-image challenge suite is **not an email-delivery test**.
It retains production mode and `DISABLE_EMAILS=true`; the production guard on the
development inbox stays in force. Its trusted fixture performs real registration,
keeps the generated synthetic password in memory, and waits for the matching
user's password hash and encrypted personal key. After checking the ownership
manifest and acceptance database identity, it locks and marks only that newly
registered, nonce-bound synthetic user verified in a transaction. It then obtains
a session through real password login. Team creation, OAuth and signing still use
that real session. No user or key is inserted by this verification setup, no raw
token is read, and passwords and sessions must not enter logs or reports.

The helper contracts run with the repository-declared command:

```sh
cd e2e
bun test helpers/challenge-image.test.ts
```

These contracts mock external I/O and check list-only suite discovery. They do
not replace a retained immutable-image acceptance run or full browser E2E.
