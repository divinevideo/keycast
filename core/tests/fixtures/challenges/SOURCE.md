# Synthetic challenge v1 fixtures

Source: https://github.com/divinevideo/divine-challenges
Immutable merged commit: `49c3e2ee8e9aa3d1a34af042c2edc78b3d2c4de6`.
Files are copied verbatim from `fixtures/v1/events.json` and `fixtures/v1/manifest.json`.
SHA-256 of `events.json`: `7a070f57f2246ab2897fc5bd7e5442ec5fc698058a2bdf10df6cc124a8858b37`.
The release manifest records 26 scenarios separately; those lifecycle scenarios are not
vendored or replayed by this permission-only foundation.
All identifiers are synthetic. No signing keys are included.

The permission tests convert only the outer record to an unsigned signing template.
Embedded snapshots remain signed records and are freshly verified. Outer signature and
signer-identity failures are intentionally outside this permission's shape boundary.

The bounded signed-field projection and audited 637-name timezone compatibility set
were adapted from `divinevideo/divine-funnelcake` commit
`cb15132e35fa1ac45d74b23b7e8a1bbf3c709967`, `crates/challenges/src/snapshot.rs`
and `crates/challenges/src/validation.rs`.
