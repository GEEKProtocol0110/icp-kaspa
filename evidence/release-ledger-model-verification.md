# Synthetic release-ledger verification — October 19, 2026

Scope: `scripts/release_ledger_model.py` and its fake-chain adapter. No real
content keys, key encryption, service attestations, RPC calls, native ticket
transactions or funded effects are exercised. Existing custody/anchor code and
live journals are unchanged.

The 44 new Python tests cover:

- Separate authority/domain signatures, exact immutable record bindings, unique
  symbolic key tags, recipient authentication and purpose/nonce replay rejection.
- Two database connections competing for one grant, shared count/byte budgets
  and a single immutable response; a submission reply racing response commit.
- Fixed budget windows, original deadlines, no automatic refunds and gate
  changes during transactions or after retrieval authentication commits.
- Exact issuance/consumption bindings, successor thresholds, stale/future,
  offline/backlogged observations and reorgs before/after response commit.
- Lost replies, one submission attempt, crash boundaries around reservation and
  effect intent; actual subprocess exit before/after response commit and restart
  retrieval of identical bytes.
- Durable clock rollback/error halts, pinned policy/epoch/budget, revocation and
  explicit uncertainty halts. Rejected requests preserve observed clock progress,
  so denial cannot hide a later backward jump. Real-adapter objects are rejected.
- Two explicit limitation counterexamples: cloned databases can each claim the
  same grant; a reorg after the final sample can precede the placeholder return.

Local verification: all **197 Python tests** pass (previous 153 + 44 new).
The full required GitHub workflow verifies **265 tests** including the existing
68 Rust tests, formatting, compiled fixtures, deployment templates, all three
synthetic demos and the native binary build. Workflow outcomes for the exact
published tree are attached to the milestone pull request. The local host has
no Cargo toolchain; Rust verification is performed there, not inferred from the
Python result.

The public [demo transcript](release-ledger-model-demo.json) contains a labeled
non-secret response and records zero keys delivered and zero real transactions.
It is not live acceptance evidence. Read [the model's trust boundaries and
limitations](../docs/RELEASE-LEDGER-MODEL.md) before interpreting these results.
