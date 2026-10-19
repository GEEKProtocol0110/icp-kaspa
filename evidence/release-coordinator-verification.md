# Synthetic coordinator verification

Date: October 19, 2026. Mode: `SYNTHETIC_COORDINATOR_NO_KEYS_NO_CHAIN`.

## Change

Added a standalone standard-library coordinator model with separate SQLite
ledger, private fake-vault outbox, delivery nonce journal and independent
fencing/checkpoint authority. It exercises cross-store failure recovery without
real keys, cryptographic grants, RPC, native transactions or network delivery.

Read [the model guide](../docs/RELEASE-COORDINATOR-MODEL.md) for exact assumptions
and the distinction between trusted admission fixtures and authenticated access.
It implements a subset of [the service design](../docs/RELEASE-SERVICE-DESIGN.md).

## Verification

- 52 new Python tests in tests/test_release_coordinator_model.py.
- Full Python suite: 286 tests. Full project suite: 354 tests, including 68 Rust.
- Required CI runs compiler/template checks, Rust formatting/tests/build,
  Python tests, all five demos and deployment-template verification.
- The local host runs Python; Rust/native checks run in the milestone's GitHub
  Actions workflow. Passing CI is required before merge.
- Public demo: release-coordinator-demo.json. It contains sanitized status and
  one random response digest, with no placeholder bytes or sensitive material.

| Acceptance case | Evidence exercised |
| --- | --- |
| Same operation across retries/restarts | Identical canonical response, original budget charge, no epoch/generation rewrap |
| Candidate remains private | Status omits candidate bytes; dispatch before commit fails |
| Cross-store commit gaps | Lost reserve/vault/response/revocation/delivery acknowledgments reconcile exact saved journals |
| Actual process termination | Child processes exit before vault commit, after durable save and after checkpoint acknowledgment |
| Fenced writers | Old writer rejected at ledger/vault/delivery paths; expired and foreign authority leases rejected at component save |
| Competing connections | Concurrent workers cannot both consume one retrieval nonce |
| Restore and corruption | Older ledger/vault/delivery backups, cloned old prefixes, tampered histories and checkpoint conflicts halt |
| Missing response dependency | Committed response without matching vault candidate halts without recreation |
| Permanent accounting | Failed reservations do not claim partially; ticket/challenge claims persist; changed/overlapping windows and epoch resets fail |
| Current eligibility | Fresh matching fake observations, original deadlines and current policy/delivery epochs required at release boundaries |
| Revocation order | Accepted revocation blocks new preparation/commit/dispatch; saved candidates, charges, used and disclosure flags remain |
| Clock continuity | Errors/backward movement latch halt, including boundary exit; failed requests preserve observed high-water mark |
| Explicit counterexamples | Restoring authority with all stores permits nonce reuse; revocation/reorg after accepted dispatch cannot recall bytes |

## Interpretation

These are synthetic software-state tests, not adversarial validation of a live
release service. The authority and component implementations share a trusted
host and codebase. Request/approval/recipient/revoker authentication, record
immutability, service attestation and issue/consume observations are trusted
fixtures here. The earlier signed ledger and HPKE lab are not integrated.

No funded session was opened or modified. No mainnet mode, endpoint, key-export
function, native signer, transaction broadcast, customer integration, audited
security, factual-truth verification or quantum protection is introduced.
