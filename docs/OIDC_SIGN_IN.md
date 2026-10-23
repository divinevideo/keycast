# Sign-in through an external OpenID Connect provider

Status: Proposed (opt-in, off unless `OIDC_ISSUER` is set)

Keycast authenticates people with e-mail and password. An operator who already runs an
identity provider (Keycloak, Authentik, Zitadel, Auth0, an EUDI-wallet bridge, …) can instead let
people sign in there: Keycast acts as an OpenID Connect relying party, verifies the ID token and
opens its usual `keycast_session`. Everything after that (OAuth consent for apps, bunker URLs,
UCAN sessions, policies) is unchanged.

Typical use: an organisation that provisions accounts itself (`POST /api/admin/preload-user`)
and wants its members to reach their managed Nostr key with the login they already have, without
a Keycast password and without a claim step.

## Flow

1. `GET /api/auth/oidc/start?return_to=<same-origin path>`: Keycast creates `state`, `nonce` and
   a PKCE verifier, seals them (HMAC with the server key, 10 minutes) into a cookie named after
   the state, and redirects to the provider's authorization endpoint (authorization code + PKCE
   S256, confidential client).
2. The person signs in at the provider.
3. `GET /api/auth/oidc/callback`: Keycast checks the state against its cookie, exchanges the code,
   verifies the ID token against the provider's JWKS (RS256 or ES256, `iss`, `aud`, `exp`,
   `nonce`; no algorithm confusion, keys refreshed on an unknown `kid` at most every 30 s), maps
   the subject to an account, sets `keycast_session` with a server-signed UCAN and redirects to
   `return_to`.

The OAuth popup (`/api/oauth/authorize`) and the web app's `/login` page show a
"Sign in with <provider>" button when the feature is configured (`GET /api/auth/oidc/config`).
From the popup, `return_to` is the authorize request, so consent continues as before.

## Account mapping

Accounts are never created by this flow.

- The first sign-in links the provider's subject to the existing account whose `vine_id` equals
  the ID token claim named by `OIDC_LINK_CLAIM` (default `keycast_vine_id`). The provider has to
  put that claim into the ID token, e.g. from a user attribute.
- Later sign-ins use the stored link (`oidc_identities`: one row per tenant, issuer and subject;
  an account has at most one subject per issuer; links are never re-pointed; they go away with the
  account).
- Unknown subjects without a matching claim get "No account" (403).

Preloaded accounts have no e-mail. Their OAuth token exchange therefore reads the e-mail as
optional (`UserRepository::get_optional_email`); before this change it answered 503 for them,
which never showed upstream because unclaimed accounts could not sign in.

## Configuration

| Variable | Meaning |
| --- | --- |
| `OIDC_ISSUER` | Issuer URL as the browser sees it; enables the feature. Must equal the discovery document's `issuer` and the ID token's `iss`. |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Confidential client registered at the provider. |
| `OIDC_REDIRECT_URL` | `<APP_URL>/api/auth/oidc/callback`, registered at the provider. |
| `OIDC_BACKCHANNEL_URL` | Optional origin for the server-to-server calls (discovery, token, JWKS) when the issuer's public host does not resolve from Keycast (Docker Compose). The `Host` header stays the issuer's. |
| `OIDC_SCOPES` | Default `openid email profile`; add the scope that carries the link claim. |
| `OIDC_LINK_CLAIM` | Claim matched against `users.vine_id` on the first sign-in. Default `keycast_vine_id`. |
| `OIDC_PROVIDER_NAME` | Button label, "Sign in with …". Default `single sign-on`. |
| `OIDC_HIDE_PASSWORD_LOGIN` | `true` hides the e-mail/password and registration forms in the login pages. The password API stays (admins and scripts use it). |

Provider side: a confidential OIDC client with the redirect URL above, the authorization-code
grant, PKCE allowed, and the link claim in the ID token.

## Security notes

- The flow cookie is `HttpOnly; Secure; SameSite=Lax`, scoped to `/api/auth/oidc`, sealed with a
  key derived from the server key, and expires after 10 minutes; each sign-in has its own cookie,
  so parallel sign-ins in one browser do not overwrite each other.
- `return_to` accepts same-origin relative paths only.
- The ID token is the only source of identity; the userinfo endpoint is not used.
- Sessions minted here are ordinary server-signed UCAN sessions (24 h) carrying the account's
  status, so suspended accounts stay suspended; each sign-in is recorded as an auth event with
  `"method": "oidc"` and the issuer.

## Out of scope (possible follow-ups)

- Creating accounts on first sign-in.
- `prompt=none` for silent sign-in from trusted apps, and logout through the provider's
  end-session endpoint.
- Several providers per tenant.
