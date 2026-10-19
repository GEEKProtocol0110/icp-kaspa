# Native fixture controller verification

October 19, 2026. ICP contributors.

Scope: persistent fixture-only controller over native transaction preparation,
using the existing trusted journal/authority model. No live-chain experiment.

- 37 new Python tests cover permanent branch choice, exact serialized outbox
  recovery, original charges/deadlines, two independent concurrent connections,
  stale generations, missing/corrupt state, unavailable/changed worker,
  synthetic reorgs and unknown-effect reconciliation without another attempt.
- Actual child processes exit after branch or terminal-outbox component commit
  and before checkpoint acknowledgment. Recovery retains the branch and saved
  record; existing outboxes are returned with signing disabled in the test.
- Four new Rust tests exercise complete saved-record round trips, malformed
  encoding, corrupted transactions/hashes and substituted original plans.
  Terminal-plan construction now computes its parent binding without signing.
- Full local verification: **516 tests = 100 Rust + 416 Python**, pinned format
  and native build checks. The existing native fixture vectors remain unchanged.
  CI builds the worker before Python tests and runs the public controller demo.
  Final-head hosted results are attached to the associated PR.
- The [public demo](native-ticket-controller-demo.json) contains hashes and
  metadata only. Private databases and signed outboxes stay outside Git.

An explicit counterexample jointly restores the authority and component and
selects a different branch after losing accepted history. Independent authority
continuity, trusted host/code/clock and correct use of the controller API remain
assumptions. The native worker can sign known fixtures independently of this
Python controller; this is not deployment-level signer fencing.

Synthetic views, revocation/approval/record digests and the one-grant accounting
are fixtures, not real authorization, a global budget or accepted-chain proof.
No real key, RPC, funded transaction, independent host, mainnet option or release
service integration is added. Next: dedicated read-only native ticket observation.
