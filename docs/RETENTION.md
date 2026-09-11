# Account-operation retention

Keycast follows the approved account-deletion retention policy recorded in
`divinevideo/support-trust-safety#204`. Complete deletion and protected-account
provisioning rows remain authoritative until Funnelcake's terminal deletion
sequence requests compaction. Keycast alerts on overdue rows but never initiates
compaction itself.

## Compaction request

`POST /api/admin/retention/compaction` is authenticated with
`KEYCAST_DELETION_SERVICE_TOKEN`. The body may contain either or both targets:

```json
{
  "deletion": {
    "deletion_request_id": "opaque-request-id",
    "pubkey": "full-64-character-hex-pubkey"
  },
  "provisioning": {
    "pubkey": "full-64-character-hex-pubkey"
  }
}
```

Deletion compaction addresses one exact request. Provisioning compaction returns
one acknowledgement for every applicable operation. `not_applicable` is an
explicit successful result when Keycast has no complete or compacted provisioning
operation for the account. A caller must retain its coordinator row whenever any
requested acknowledgement has `durable: false`.

## Digest keys and rotation

Configure `KEYCAST_RETENTION_DIGEST_KEYS` as:

```text
current=v2;v1=<64 lowercase hex characters>;v2=<64 lowercase hex characters>
```

Each value is an independently generated 32-byte secret. Keycast derives separate
purpose keys and applies separate message domains for deletion bindings,
provisioning request fingerprints, and provisioning account bindings. Never reuse
these roots in another service or export the resulting digests.

To rotate, add a new version and make it current while retaining every version
still referenced by a tombstone. Removing a referenced version makes verification
fail closed. Retire an old key only after no tombstone records its version.

## Legal holds and review

`retention_legal_holds` contains narrow references rather than narratives. An
authorized operator records the authorizing role, exact deletion-request or
account-binding scope, external reason reference, start, required review date,
optional expiry, and release. Disposal queries check active holds transactionally and resume the
original clock after release.

Privacy/legal and the Keycast owner must review indefinite replay tombstones at
least annually; the next review is September 2027. Tombstones remain necessary
until all relevant services use bounded, cryptographically verifiable operation
IDs and the approved migration, replay, retention, and hold conditions are met.
