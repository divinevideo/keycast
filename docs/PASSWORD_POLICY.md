# New password policy

New passwords use `keycast_core::password_policy::validate_new_password`:

- At least eight Unicode characters after ignoring surrounding whitespace.
- Reject the bounded common-password list in that module, ignoring ASCII case
  and surrounding whitespace. This is not a breach-corpus lookup or an entropy score.
- No uppercase, digit, or symbol requirement; passphrases are supported.
- The submitted value is hashed unchanged, including any surrounding whitespace.

The policy applies to browser registration (`/api/auth/register`), native
registration (`/api/headless/register`), OAuth popup registration
(`/api/oauth/register`), password reset (`/api/auth/reset-password`), authenticated
password changes (`/api/user/change-password`), and account-claim submission
(`/api/claim`). Claim confirmation uses the hash already staged at submission.
Verification PINs and OAuth connection secrets are not account passwords.

A rejected new password returns HTTP 400. JSON endpoints return
`code: "WEAK_PASSWORD"` and
`error: "Use at least 8 characters and avoid common passwords."`.
The HTML claim form displays the same guidance and sends
`X-Error-Code: WEAK_PASSWORD`. Clients should display this guidance and may map
the code to localized copy. Existing Keycast web forms display server error messages.

The policy does not run during login or other current-password verification.
Existing hashes remain valid, and no user is required to reset a password.
