# Observer/controller integration verification

Date: October 19, 2026. Scope: offline native fixtures and synthetic chain scans.

- The observer-bound fixture controller commits exact tracker configuration,
  plans and native semantic pins into a distinct controller policy. Its original
  branch, charge, outbox and attempt journal remains under the existing trusted
  authority/checkpoint model.
- Two new native tests verify unsigned pin semantics/IDs against signed native
  fixtures, omit signature/VM/full-hash claims, detect changed context and reject
  nonfixture funding sources. The worker's `pin` operation never signs.
- Thirty-four new Python tests exercise the actual native worker and projector
  through the connected controller: exact unspent observations, successor depth,
  separate freshness limits, wrong/missing views, restart/reopen, changed pins,
  incompatible policy, expired/refund paths, lost replies, reorgs and restores.
  Clock resampling also blocks reads that finish stale or cross the original
  deadline while still inside the freshness limit.
- A reorg between durable intent and the final serialized check blocks the
  synthetic effect without allowing an automatic retry. A separate explicit
  counterexample changes the chain after the last sample: the fake effect still
  occurs. There is no atomic chain-to-signing/effect guarantee.
- Full local suite: **598 passing tests (110 Rust + 488 Python)**. Locked native
  builds, formatting, both contract compiler checks, the offline integration
  demo, documentation links and source checksums also passed locally.
- [Public demo](native-ticket-binding-demo.json) contains only synthetic result
  flags, branch and charge. Known-key signed fixtures are temporary/private and
  are not published. The milestone made no live RPC calls or broadcasts.

The original fake-map controller remains separate. Its default policy encoding
is unchanged, while observer-bound stores require their distinct policy identity.
Worker binaries remain hash-pinned: rebuilding a worker is not an automatic
migration for an existing store. Preserve its original binary and private files.

All effects remain strictly local `FakeNode` operations. No funded native ticket,
actual permission, adopted N0/R0 wire protocol, real data key, independent signer,
production finality, audit or quantum-safety claim is supplied. Nodes, host,
configuration, storage and clock are trusted. Joint service/authority rollback
and direct known-key worker use remain limits. See [the guide](../docs/NATIVE-TICKET-BINDING.md).
