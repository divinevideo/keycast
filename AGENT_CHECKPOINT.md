# Distributed custody research checkpoint

## Objective and status

[VERIFIED] Research, a proposed architecture and a gated synthetic-prototype plan
are committed on `docs/distributed-custody-research`, based on freshly fetched
main `df350e30bcca683aa70465036f99eda9b7fab6fb`. Current authorization is research
and planning only. No prototype or serving changes were made. The PR is the
source for remote checks and assigned human review; no merge/deploy authority.

## Verification

[VERIFIED] Documentation local links/fences and `git diff --check` passed.
`cargo fmt --all -- --check` passed. Workspace all-target/all-feature clippy
passed with `-D warnings -A deprecated` and offline SQLx. No product tests were
added or locally rerun for this documentation-only change. Source research is
not interoperability or adversarial execution evidence.

## Mental model to preserve

- Machine signing quorum and human publishing policy are different. Ordinary
  content still needs one authorized human, regardless of service share count.
- 2-of-3 signing is not 2-of-3 agreement on mutable authority. Proposed all-three
  policy votes persist fences; missing nodes/stalled preparation reduce liveness.
  Never add a local timeout-unlock while retaining the safety claim.
- Device enrollment/bootstrap and recovery must be independently verifiable.
  Moving shares while trusting coordinator-only authorization leaves signing
  authority centralized. Existing HTTP UCAN/DPoP is retained but is not by itself
  the event-and-context approval needed by each guard.
- Candidate FROSTR runtimes and the existing pinned official suite have different
  dependencies, package/wire and lifecycle contracts. Identical version numbers
  do not establish interoperability. Dealer/reconstruction helpers are excluded.
- Bunker transport-key derivation currently needs the complete identity secret.
  A new custody profile needs independent transport keys and an explicit client
  compatibility/re-enrollment decision.
- Backup plaintext authority must remain separated. Restored participant IDs
  retain their quorum weight; new incarnation fencing precedes signing, and no
  live nonce state is restored.
- The group implementation is unmerged PR #435 at the inspected head documented
  in the research. This branch is independently based on main, not stacked on it.

## Remaining decisions and unverified claims

[UNVERIFIED] FROSTR DKG/package/signing interop, pre-sign guard integration,
process-kill/snapshot safety, real device proof/recovery UX, cloud authority
separation and performance require the proposed experiments. The written plan
records tests, evidence gates and fallback selection; none ran in this task.

[UNVERIFIED] Recovery factors/operators, all-three mutation availability,
client/method parity and migration behavior need explicit product/security review
before production planning is final. Do not implement or change live custody
based on a proposed document alone.

## Next steps

1. Inspect this branch's PR/checks and the private source-review conclusion.
2. Have the product/security owner review the design's production decisions.
3. Only after design/plan approval, choose an execution method and run the
   synthetic prototype plan. No cloud or personal-key migration is implicit.

## Documents

- `docs/research/2026-10-16-distributed-custody.md`: source pins and findings.
- `docs/superpowers/specs/2026-10-16-distributed-custody-design.md`: proposed model.
- `docs/superpowers/plans/2026-10-16-distributed-custody.md`: gated prototype tasks.
