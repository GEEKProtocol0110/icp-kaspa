# Signed coordinator verification

Date: October 19, 2026.
Mode: `LOCAL_SIGNED_COORDINATOR_SYNTHETIC_RESPONSES_NO_CHAIN`.

## Change and scope

Added a distinct signed lab over the separate-store recovery coordinator:
complete approver/sender permission signatures, service-issued challenges,
recipient admission/retrieval signatures and sequenced revoker authorizations.
Protected base helpers keep evidence and used nonces atomic with the relevant
ledger reservation or delivery decision. Original model behavior and tests
remain, in their separate unsigned harness.

Responses are non-secret placeholders. All chain/record/delivery-binding inputs
remain synthetic fixtures. This is not an adopted R0 encoding, integrated HPKE
key release, transport service, native effect or production fencing deployment.
Read [the guide](../docs/SIGNED-COORDINATOR-LAB.md) for schemas and limits.

## Checks

- 48 new tests in tests/test_signed_coordinator_lab.py.
- Full local Python suite: 334 tests. Full project suite: 402 tests including
  68 Rust tests; required Rust/build/template checks run in GitHub CI.
- The required workflow also runs all six demos. Passing final-head CI is
  required before the milestone merges.
- Public synthetic transcript: signed-coordinator-demo.json. It prints public
  signatures/labels, status and digests, with no private keys, plaintext record
  or pending response bytes. Private values used by a crash test pass only
  through its child-process stdin and are never written into public evidence.

| Case | Observed behavior |
| --- | --- |
| Wrong/missing roles or changed context | Both permission signatures and exact recipient identity required before claims/charges |
| Wrong purpose/version/service/budget/policy | Strict new namespace, exact fields and purpose separation reject reuse |
| Unintended client challenge | Recipient helper checks expected permission and expected committed-response digest before signing |
| Replayed, unissued, expired or old-generation proof | No new reservation or dispatch; used nonces and original charges persist |
| Permission/request/response substitution | Exact admission and response digests remain bound to the original operation |
| Interrupted saves | Nonce/evidence and reservation/delivery share one durable event; lost acknowledgments reconcile the saved state |
| Actual process termination | Child exits after ledger commit before independent acknowledgment; restart recovers both signed proof claim and single charge |
| Rejected quota request | No partial grant claim or consumed admission nonce |
| Stored authorization corruption | Integrity halt before placeholder preparation |
| Revocation | Exact grant/permission, distinct signer, short signing interval, global next sequence and unique ID required; accepted revocation blocks previously signed retrieval |
| Revocation recovery | Lost acknowledgment retains revocation; exact accepted retry is idempotent without refund/history deletion |
| Eligibility changes | Fake reorgs, inactive epochs and original deadlines still block valid signatures |
| Explicit limits | A copied signed request can be relayed once; restoring the authority with every store loses an accepted revocation |

No private custody session was opened, no mainnet switch was added, and no
content key, RPC request, funded ticket, native signature or broadcast was created.
This does not establish human identity, legitimate intent, factual truth,
quantum safety or an independent security audit.
