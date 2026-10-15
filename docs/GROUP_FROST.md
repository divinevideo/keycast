# Optional threshold groups

Ordinary groups use hosted custody and one authorized admin can publish. FROST
is an explicit, separate custody choice with a real threshold of at least two.
There is no threshold-one workaround, automatic Keycast vote, server-held signing
share, or NIP-46 partial-signature extension. An encrypted recovery copy does not
authorize the coordinator to participate in signing.

The implementation pins `frost-secp256k1-tr = "=2.2.0"` and uses its untweaked
`round2::sign` / `aggregate` operations. The wire descriptor is
`keycast-frost-v1/secp256k1-tr-2.2.0/untweaked`; backup bindings use ciphersuite
`FROST-secp256k1-SHA256-TR-v1` and tweak version `untweaked-v1`. No BIP-341
Merkle-root tweak is applied. Final results are ordinary NIP-01 events with the
standard event ID and 64-byte BIP-340 signature.

## API and identity binding

The account-management UCAN boundary authenticates all coordinator requests;
third-party signing grants cannot manage these ceremonies. All operations check
tenant, current human-account status and active group membership in Postgres.
Public signing work runs on a bounded blocking executor path with admission
control. A transaction locks the group, membership rows and current human records;
there is no nested pool acquisition, KMS operation or outbound request while
holding it. Single-connection-pool integration coverage exercises this contract.

Create a pending group in `frost` mode using the regular group API, invite admins,
and let every invitee accept before beginning DKG. The FROST router lives at
`/api/groups/:group_id/frost`:

| Method and suffix | Body / result |
| --- | --- |
| POST `/dkg` | Fresh UUID `session_id`, `threshold`; returns DKG state |
| POST `/signing` | Fresh UUID `session_id`, completed `dkg_session_id`, full unsigned `event`, immutable `signer_ids`; returns proposal |
| GET `/sessions/:session_id` | Public protocol state and recipient ciphertexts |
| POST `/sessions/:session_id/dkg` | Signed Nostr protocol envelope |
| POST `/sessions/:session_id/signing` | Commitment or partial with `proposal_digest`, or abort |
| POST `/sessions/:session_id/abort` | Abort an unfinished operation |

Session IDs are never recycled. Pending sessions expire after 15 minutes. The
completed DKG public package remains identity data after that deadline. Retrying
identical public messages is safe; contradictory authenticated duplicates abort.
Completed DKG identities and completed signing results are immutable: authenticated
late duplicates return the original result after timeout, and conflicting late
traffic is rejected without changing that result. Current requester authority is
still required. A final signature is never recomputed to answer a retry.
Creating a signing session pins exact event fields, canonical event ID, all signer
identities/participant IDs and their current membership/device epochs. Each
selected participant must already have a current durable share backup; the API
returns an actionable backup-required error otherwise. Public-key generation alone
does not mean participants are protected by recovery.

Participant IDs are allocated once in bytewise admin-key order from a monotonically
increasing group counter implicit in the highest assigned membership ID. Existing
IDs are retained across removals, retries and device recovery and are not reused
for another identity. The DKG descriptor binds the full ordered roster, threshold,
protocol, tenant, group, key/roster versions and session. After key generation,
adding participants or changing the cryptographic roster/threshold requires a new
group identity. Removing an admin revokes coordinator and recovery access, while
remaining active participants may still sign if they satisfy the original
threshold. A retained share cannot be cryptographically revoked without changing
the identity. Removal does not change the public key or pretend to revoke a
retained share.

## Dealerless key generation

The native `client::DkgRound1` / `DkgRound2` handles implement the client side:

1. Explicit human approval pins the descriptor and generates a real ZF DKG
   round-one contribution. A kind-21146 Nostr event authenticates its complete
   application payload. This custom application kind does not claim Mantra or
   ChillDKG compatibility.
2. Every participant receives all round-one events and signs the digest of the
   same complete, canonically ordered transcript. Clients verify every signature,
   identity, binding and digest. Missing or conflicting agreement prevents round
   two. The coordinator is not trusted to replace broadcast agreement.
3. Only after every agreement, each participant produces a distinct round-two
   package per peer. NIP-44 v2 encrypts it to that peer's Nostr identity; the outer
   signed event and the inner encrypted payload both bind the complete ceremony,
   sender, recipient and transcript. The coordinator stores ciphertext and cannot
   decrypt delivery. A nonrecipient cannot consume another peer's package.
4. Each client verifies/decrypts all expected contributions, runs real DKG part
   three, and signs its complete public package plus transcript digest. The group
   public key is installed only after all roster members confirm the identical
   package. Clients independently verify all final confirmations before signing.

Any invalid contribution, missing peer, mismatch or lost secret handle requires
aborting and starting with a fresh UUID and fresh randomness. No inbound message
generates a contribution without an explicit client call/approval.

### Hosted human identities

The reference native DKG helpers currently accept local authentication `Keys`.
They must not cause a client to export an unrelated hosted personal identity key.
The HTTP protocol accepts ordinary signed envelopes independently of those
helpers: a client with a hosted human identity may use its existing NIP-46 signer
for `sign_event`, `nip44_encrypt` and `nip44_decrypt`, with an explicitly authorized
policy permitting the protocol kind. The existing account-managed
`POST /api/user/bunker/create` accepts `policy_slug:null` for an explicitly approved
full-access personal connection; the default social policy is not assumed to
permit kind 21146. The mobile/native adapter for remote authentication is client
integration work, not provided by these synchronous reference handles. A restored
participant can approve/sign through authenticated coordinator HTTP operations
without possessing the human identity's private key. Independent groups use local
transport/authentication keys and have no such Keycast connection.

## Signing and crash safety

The native `Participant` retains the share. The app displays and approves the
complete event and signer set once, then `Participant::approve` produces an opaque
`Approval` and public commitment. `Approval` has no cloning, serialization, debug,
seed or nonce-export API. Its consuming `sign` method checks exact approved bytes,
signer set and its own commitment, and consumes/wipes its nonce on success or error.
The share and DKG secret handles also wipe held material when dropped. A native
bridge must preserve these ownership rules and keep handles outside Dart/JS.

Keycast permanently reserves both public nonce points independently per identity,
including on abort, in `group_frost_commitments`. Group-row locks and unique
constraints make reuse checks atomic across workers. Even reusing one point with
a different companion is rejected. Identical commitment and partial retries are
idempotent. Clients resend the already-produced public partial after a lost
response; they never invoke signing again with its old approval. The pinned
library verifies all shares during aggregation; the resulting event is also
verified by the ordinary Nostr implementation before release. Audit rows bind
the acting admin, session and resulting event ID without storing private payloads.

The durable ledger complements client ownership; **a restored database cannot
prove that an old client nonce is unused**. After client process death, device
restore, coordinator restoration/rollback, uncertain delivery, or loss of native
state, abort every pending ceremony/approval and start a fresh UUID with freshly
generated nonces. Never restore or regenerate nonces from a saved seed, serialize
approvals, or continue a pending signing session after recovery. Before serving a
restored coordinator, operators must mark every unfinished FROST session aborted
and retain the commitment ledger. Completed DKG identities and final public events
remain intact. These are mandatory integration/operational requirements, not a
claim that a SQL ledger alone survives an arbitrarily old snapshot.

`Participant::export_for_encrypted_backup` exports only the long-lived key package
for the authenticated encrypted backup API. Recovery restores the same participant
ID; it creates no extra quorum vote. Backup validation compares the real key/share
to the authoritative confirmed public package. Restoring increments the device
epoch, invalidates pending sessions, and requires fresh proposals/approvals with
current epochs. No personal key export or server signing participation is enabled.
Server-recoverable copies of a threshold of shares are custodial material even
though this coordinator has no share-signing API.

## Self-management and verified scope

Self-managed groups need no Keycast account, registration, transport, backup or
signing endpoint. They can exchange the same signed recipient envelopes through
their own transport, use `DkgState` plus native client handles for ceremony
validation, and construct/aggregate a `SigningState` locally with public
commitments and `add_partial`. They own durable nonce exclusion and recovery;
public list state remains readable directly from relays. No server registration
is needed to verify final events.

`core/tests/group_frost_test.rs` exercises dealerless 2-of-3 DKG through Postgres,
all three signing subsets, standard relay publish/readback and ordinary Nostr
verification, single-connection pools, transcript disagreement, missing agreement,
recipient confidentiality, changed approvals, commitment reuse after abort, device
epoch invalidation and restoration of the same share. The shared fixture also
supports real-share backup/restore integration tests. Mobile UI/native bridge
integration, physical-device ceremonies and independently audited client
key-management deployment remain separate work; this API is not evidence that
those clients have shipped. No production deployment is part of this change.

Upstream reference: [ZF FROST 2.2.0 API](https://docs.rs/frost-secp256k1-tr/2.2.0/frost_secp256k1_tr/).
