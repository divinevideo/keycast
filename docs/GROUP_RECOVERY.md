# Group recovery

Group recovery requires an authenticated current human administrator. A removed
administrator cannot restore a package, including by retrying a previously
successful request. Other administrators and tenants cannot download it.

Hosted groups retain their signing key in `stored_keys`, encrypted by the configured
KeyManager. The status endpoint checks current membership, decryptability and the
matching public key. Hosted keys are never exported through the backup endpoint;
replacement devices use fresh group enrollment. Personal keys are never accepted
as hosted recovery material.

Device groups back up the actual full signing key. FROST groups back up the actual
serialized FROST KeyPackage and PublicKeyPackage for that administrator's permanent
participant identifier. A FROST share is never parsed as a full private key. The
server validates the scalar/public share, identifier, public key and threshold.

## API and package version

All routes use the existing tenant extractor and account-management UCAN authority
(see [GROUPS.md](GROUPS.md)); delegated third-party signing tokens are refused:

- `PUT /api/groups/:group_id/backups` uploads `{request_id,binding,material}`.
- `GET /api/groups/:group_id/backups` returns current custody, `recoverable` and
  `backup_request_id`, the latest validated package ID for the current member and
  group versions. Hosted custody and missing current packages return a null ID.
- `POST /api/groups/:group_id/backups/restore` accepts
  `{request_id,backup_request_id}` and returns the package and installation epoch.

`binding` contains `format_version` (1), `tenant_id`, `group_id`, full
`group_pubkey`, full `admin_pubkey`, nullable `participant_id`, `membership_version`,
`key_version`, `roster_version`, `ciphersuite` and `tweak_version`. The encrypted
plaintext includes the entire binding and package. Every download checks the
binding against current durable membership and versions after decryption and again
under group/member locks immediately before committing recovery.

`material` is a strict tagged object. `kind: full_key` contains a 64-character hex
`secret_key`; `kind: frost_share` contains hex binary `key_package` and
`public_key_package` using frost-secp256k1-tr exactly 2.2.0. Unknown fields are
rejected. Nonces, nonce seeds, pending session handles and session credentials do
not belong in these packages. Package-bearing structs have no Debug implementation
and zeroize secret strings and temporary plaintext buffers when dropped.

Full-key bindings use `ciphersuite:"BIP-340"` and `tweak_version:"none"`;
FROST bindings use `ciphersuite:"FROST-secp256k1-SHA256-TR-v1"` and
`tweak_version:"untweaked-v1"`. For example, after reading the current versions:

```json
{
  "request_id": "<stable-backup-request-id>",
  "binding": {
    "format_version": 1,
    "tenant_id": 1,
    "group_id": 42,
    "group_pubkey": "<full-group-pubkey>",
    "admin_pubkey": "<full-current-human-pubkey>",
    "participant_id": 1,
    "membership_version": 1,
    "key_version": 1,
    "roster_version": 1,
    "ciphersuite": "FROST-secp256k1-SHA256-TR-v1",
    "tweak_version": "untweaked-v1"
  },
  "material": {
    "kind": "frost_share",
    "key_package": "<hex-serialized-KeyPackage>",
    "public_key_package": "<hex-serialized-PublicKeyPackage>"
  }
}
```

A full-key package instead uses `participant_id:null` and
`material:{"kind":"full_key","secret_key":"<full-hex-group-secret>"}`.
Never log the request/response body. On a replacement device, fetch backup status
first and use its `backup_request_id`; the lost device's upload ID does not need
to be retained locally. Restore with
`{"request_id":"<fresh-recovery-id>","backup_request_id":"<ID-returned-by-status>"}`;
the response is `{binding,material,installation_epoch}`. Hosted status instead
reports custody/recoverability and versions without exporting its key.

Upload success follows the database commit and returns its committed
`backup_request_id` in the status response. A failed storage or encryption request
returns an error and must never be displayed as recoverable. Retrying an upload
with the same request ID and identical contents preserves the original package;
different contents conflict. Use a new ID for changed material. A roster, membership
or key version change makes older packages obsolete and requires a new upload.

Restore retains the FROST participant identifier, increments installation epoch,
revokes previous device grants, and aborts pending coordinator sessions atomically.
A lost response can be retried with the same recovery request ID. A later recovery
makes the prior request obsolete. Enroll a new device for fresh credentials after
recovery. Clients must discard every pending signing session, precomputed nonce,
nonce seed and partial signature and generate fresh randomness before signing.
Do this after process death and database restoration too: rolling a database back
cannot roll client nonce history forward. Permanent coordinator commitment
reservations are retained, including reservations from aborted sessions.

## Disaster recovery is separate from upload

A committed encrypted row is recoverable application storage, not an independent
disaster-recovery backup. Recoverability after losing the database requires both a
separately retained PostgreSQL backup and access to the correct encryption key.
Neither the ciphertext alone nor a replacement encryption key can recover secrets.

The operator must configure and verify scheduled database backups and point-in-time
recovery in the environment actually serving traffic. Retain an encrypted logical
archive outside the database account/failure domain with restricted read access,
retention and a restoration drill. Include all group tables, stored keys, membership,
grant/revocation and permanent FROST commitment records; restore the complete
consistent database rather than copying only package rows.

For file KeyManager, separately escrow the exact `master.key` through an approved
secret backup system. Keep it out of source control and database dumps. For KMS,
retain the configured key resource/version, service identity recovery path and IAM
procedure; prevent premature key destruction. Database backup completion does not
prove KMS recovery. Do not log decrypted material during verification.

## Isolated local restore drill

Use synthetic identities and a dedicated local PostgreSQL instance. Never point
these commands at a deployed database. Supply connection strings through local
variables without printing them. `source_db` and `restore_db` must identify distinct
local databases, and `restore_db` must be empty.

```sh
umask 077
pg_dump --format=custom --file=group-recovery.dump "$source_db"
pg_restore --exit-on-error --no-owner --dbname="$restore_db" group-recovery.dump
```

Restore access to the original encryption key separately. Start the application
against the restored database with that KeyManager, sign in as a synthetic current
admin, check backup status, restore using a fresh request ID and enroll a new device.
Verify the returned signing material produces the same full public key, previous
grants are denied, pending sessions are aborted, and a removed synthetic admin is
denied. Repeat with the key unavailable and confirm recovery fails closed. Remove
the synthetic database, protected archive and temporary key after recording only
non-secret results. This drill tests backup restoration; production scheduling,
retention, storage independence and access recovery need separate operator evidence.

A local synthetic drill on 2026-10-16 exercised `pg_dump --format=custom` and
`pg_restore --exit-on-error` into a separate empty database, using the real file
KeyManager and the same separately held development encryption key. The restored
package decrypted to the identical synthetic signing key, recovery advanced the
installation epoch, and a removed administrator was denied on retry. The protected
archive, temporary executable source and both drill databases were removed. This
is local restoration evidence; no production backup schedule or KMS recovery was
inspected or changed.
