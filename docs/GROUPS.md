# Recoverable group identities: client contract v1

A hosted group has one Nostr pubkey and a dedicated encrypted stored key. Each
current admin can publish independently through a separate device-bound NIP-46
authorization. Other admins need not be online. This does not use threshold one
FROST. All results are ordinary NIP-01 events with standard BIP-340 signatures.
Published relay events remain the public source of truth, including list contents.
The database governs private membership, signing permissions and recovery.
Never encode owners/editors in a NIP-51 list's `p` tags; those are list members.

## Authentication and capability discovery

Routes below use the existing UCAN Bearer token or `keycast_session` cookie and
Host-derived tenant. Group custody requires the same authority as account
connection management: a user-signed session, a server-signed non-OAuth account
session, or a first-party OAuth authorization. A delegated third-party signing
token cannot enroll clients, change membership or recover material. Existing
DPoP binding checks apply. A service administrator role is not required.

`GET /api/groups/capabilities` is public and returns protocol versions, default
`hosted` custody, one ordinary human approval, backup support and FROST suite.
`server_frost_participant:false` means this release never silently adds a service
share. Capability discovery itself is optional for self-managed clients.

HTTP 400 rejects malformed/unsupported requests; 401 needs authentication; 403
means current group/account authority is absent; 409 is an idempotency or version
conflict; 503 means retry after the indicated delay. Never interpret an error as
permission to change custody mode. Sensitive credential/material responses carry
`Cache-Control: no-store`. Do not log them or place them in analytics or crash
reports.

## Hosted creation and discovery

```http
POST /api/groups
Authorization: Bearer <account-session>
Content-Type: application/json

{"request_id":"<random-stable-creation-id>","name":"Our video group"}
```

Save the request ID before sending. Retrying with the same tenant/admin/request ID
and identical configuration returns the same group ID/pubkey. Reusing it for a
different configuration returns 409. The group, first admin, policy and encrypted
key commit together; no creation response contains private signing material.
Default mode is `hosted`; `mode:"device",pubkey:"<full-group-hex-pubkey>"` registers
a device-held identity for assisted backup, and `mode:"frost"` creates a pending
threshold group whose pubkey is set only after the ceremony completes.

Response fields: `id`, `tenant_id`, `name`, `mode`, `pubkey`, `signing_key_id`,
`policy_id`, `key_version`, `roster_version`. The initial hosted group policy
permits ordinary NIP-46 operations without an event-specific approval quorum.
`GET /api/groups` lists active memberships; `GET /api/groups/<id>` retrieves the
configuration. These routes work after ordinary account recovery, without the
lost device or its keys. Hosted discovery does not export personal identity keys.

## Invitations and membership

- `POST /api/groups/<id>/members` with `{"admin_pubkey":"<full-human-pubkey>"}`
  invites that human account. The pubkey is the Keycast recovery principal,
  not a device key. No email/secret invitation link is required.
- `GET /api/groups/invitations` lets an authenticated invitee discover pending
  invitations. An invitee may accept only their own invitation using
  `POST /api/groups/<id>/accept` (empty body).
- `GET /api/groups/<id>/members` returns current/invited/removed memberships,
  lifecycle versions and, where assigned, stable participant IDs.
- `DELETE /api/groups/<id>/members/<full-human-pubkey>` removes access. At least
  one active admin must remain. Hosted group pubkey remains unchanged.

Membership changes serialize on the group row. Removal retains a tombstone,
increments its lifecycle version and installation epoch, and revokes mapped
grants atomically. Re-inviting the same person never revives their old grants.
Legacy administrative team mutation routes cannot modify these identities.

A finalized FROST group cannot add participants in place. Create a new identity
and explicitly migrate public coordinates if the cryptographic roster changes.
Removing access to coordination and recovery cannot erase a retained device full
key/share; see the threshold contract for the distinction.

## Per-admin, per-device signing

```http
POST /api/groups/<id>/access
Authorization: Bearer <account-session>
Content-Type: application/json

{"client_pubkey":"<full-NIP46-client-pubkey>"}
```

The response contains `authorization_id`, `group_pubkey`, `bunker_pubkey`,
`bunker_url`, `client_pubkey`, `key_version`, `installation_epoch`.
Treat the bunker URL as a credential. Use a different device/client key for every
installation; never share a bunker secret between admins. Enrollment returns
fresh credentials each time; retrying it cannot create a new group identity.

Use ordinary NIP-46 against the returned bunker pubkey/relays. A `connect` with
the supplied secret can only bind the already-approved client. `get_public_key`
returns the group identity. Build `sign_event` using that author; the signer uses
the group stored key and ordinary event serialization. It does not publish the
event for the client: publish the signed result to the group's chosen relays and
reconcile acknowledgments/read-back as for any Nostr event.

`GET /api/groups/<id>/access` lists grants with human/client, policy, key and
lifecycle bindings and revocation/expiry, without their secrets.
`DELETE /api/groups/<id>/access/<authorization_id>` revokes a device grant.
Membership/key/installation versions are checked in Postgres on every group
request, including cached handlers on other instances. A post-sign locked check
and durable audit happen before releasing a result. Stale service caches cannot
substitute for membership. The resulting public event ID and acting human admin
are recorded without logging bearer/bunker secrets or event plaintext.

## Replacement devices and backups

After recovering the ordinary account, rediscover groups, generate a new NIP-46
client key locally, and call `POST /api/groups/<id>/recover` with the same request
shape as `/access`. This revokes that human's previous hosted grants, advances
the installation epoch and issues fresh credentials under the original group
pubkey. It never revives old bearer tokens. Recovering one admin does not revoke
another admin. Other ordinary enrollments can coexist for multiple devices.

Hosted custody preserves the encrypted group key and recoverable membership;
it does not require an admin to download that key. Device and threshold modes
must upload their actual validated full key or individual participant key package.
See [GROUP_RECOVERY.md](GROUP_RECOVERY.md) for backup API bindings, strict payloads,
idempotency, durable acknowledgment, replacement installation behavior and the
database/encryption-key disaster-recovery procedure.

## Optional threshold groups

See [GROUP_FROST.md](GROUP_FROST.md). The coordinator protocol is versioned and
uses the exact `frost-secp256k1-tr` 2.2.0 suite with explicit tweak semantics.
It is not compatible with Mantra ChillDKG envelopes. Human approval binds the
complete exact event and signer set; fresh nonces are required after failure,
process death and recovery. Nonce state never belongs in a backup.

Keycast can technically sign if it can recover a threshold of participant
backups. Encryption at rest does not make such custody noncustodial. Backup
custody, configured participation and human approval are separate concepts.
This release has no server-held FROST participant.

## Independent mode: no Keycast dependency

The advanced client option `self_managed` is a client mode, not a required
registration call. Do not create an entry in Keycast, request its authentication,
sign transport messages with its bunker, query its capabilities at startup, or
upload/recover key material. Use a locally held full group key for any-admin
publishing or independent FROST shares for a genuine t-of-n quorum (t >= 2),
with client-owned authenticated confidential transport and transcript agreement.
Use the group's local/offline backup and verify restore during enrollment.

Reading public content and publishing signed events uses ordinary relays when
Keycast is unavailable. Divine cannot recover independent material. Full-key
holders remain able to sign until the identity rotates; old threshold holders
remain able to sign if they retain a quorum. Never silently switch to hosted
custody following a failure. Turning off assisted recovery does not erase
previously retained server backups; exclusive device custody requires a new key.

## Local acceptance demonstration

Tests use synthetic humans and isolated infrastructure. Run the repository
migrations against a dedicated local database, generate a local master.key, then:

```sh
cargo test -p keycast_core --features integration-tests --test group_lifecycle_test --test group_backup_test
cargo test -p keycast_api --features integration-tests --test group_http_test
cargo test -p keycast_signer --features integration-tests --test group_signing_test
cargo test -p keycast_core --features integration-tests --test group_frost_test
```

Set `DATABASE_URL` to the isolated local database and `BUNKER_RELAYS` to a local
relay URL. The signing suite starts a stock embedded test relay, publishes three
independently signed group events, and reads them back with a separate client.
The FROST suite runs actual DKG/signing through the coordinator and validates a
standard Nostr signature. These tests do not demonstrate physical mobile devices
or a visible rendering in another client; mobile integration owns those gates.
