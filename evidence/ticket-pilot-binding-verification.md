# P0 observation/private-preparation binding verification

Date: October 21, 2026. Scope: new-signature gates; synthetic node observations.

- A distinct P0 pair/controller policy binds the complete review, two observer
  configurations, paths, native build identities and freshness policy. Offline
  and observation-bound private journals cannot be relabeled or interchanged.
- New issue/terminal signing and new branch selection check actual current
  trackers. Signing metadata must match both nodes' exact positive UTXO entry.
  Cached public reports and caller-supplied eligibility flags cannot replace it.
- The gate resamples trusted time after saved-record verification, after status
  reads and after key-file reads. It runs before signing reservation, before
  key access and before the native signer. Lost/expired observations after
  reservation leave a permanent unknown signing outcome, not a retry.
- Thirty-two new Python tests cover successful issue/consume/refund preparation,
  node/entry disagreement, empty input rejection before reservation, stale
  chain/UTXO samples, slow reads, reorgs
  between reservation and signing, observer reopen/reconciliation, recovery,
  lost acknowledgments, unknown signer replies, source exclusivity, policy and
  backup separation, and component restore behind independent checkpoints.
- A post-sample counterexample invalidates an observer inside the signer call:
  a signature is still prepared and saved. No atomic chain-to-signing guarantee
  is claimed. Direct key/worker use and joint trusted-store rollback remain
  explicit limits from the preceding private preparation milestone.
- Full inventory: **726 tests (126 Rust + 600 Python)**. Local checks include
  locked Rust testing, all Python tests, formatting, both contract compilers,
  the unchanged public P0 review, existing controller/observer demos,
  documentation links and source digests. Final-head push/PR CI is required
  before merge.

New tests use ephemeral private role files and fabricated accepted-chain/UTXO
pages; their native signatures are real offline test signatures. The binding
performs no live RPC or submission. No operational key bundle, funded P0 run,
funding request, broadcast or data-key release was created for this milestone.
See [the binding guide](../docs/TICKET-PILOT-BINDING.md).
