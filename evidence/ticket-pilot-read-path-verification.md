# P0 live read-path verification — October 22, 2026

The initial funded preflight verified two 24,000,000-sompi sources on both TN10
nodes, then failed before signing. Three preflight profiles were retained and
halted with zero claims, signing intents, signed outboxes and submission intents.
No pilot fee was spent. Failure records included an older-history timeout, a
removed bootstrap tip, later ineligible paired observations and a failed
parallel diagnostic. The latter also exposed a local harness thread-affinity
error, which was corrected; it is not presented as a consensus failure.

## Implemented repair

- A closed canonical public `observe-p0` request opens one native connection,
  reads both role UTXOs together, then reads accepted history. Node health and
  network gates apply before and after the read sequence. All samples retain
  the caller's request-start timestamp and their actual shared node-tip brackets.
- The sampled node target is preserved across partial history pages. The last
  returned block cannot stand in for catch-up completion. Existing branch,
  successor, exact native-body/entry and two-node checks remain authoritative.
- A read-only bootstrap helper walks twenty selected-parent edges and requires
  a current selected-chain candidate. It creates no database and claims no
  finality. A later bootstrap-crossing reorg still halts the tracker.
- Native reads have a 25-second connection/read budget and bounded disconnect.
  Relay task exceptions are retrieved, the opposite direction is cancelled and
  peer closure is bounded, without printing remote error content. The existing
  upstream frame and native output limits remain explicit availability limits.
- The read profile participates in policy identity. Old databases and private
  journals cannot be silently relabeled, widened or reopened with new build pins.

## Live read-only evidence

The [recorded probe](ticket-pilot-read-path-live.json) used the exact funded
consume-run source and two configured TN10 hosts. Both reported matching ordinary
UTXO metadata, and both source sample brackets occurred in order on the scanned
branch. The existing P0 observer returned `TWO_NODE_SOURCE_UNSPENT_OBSERVED` on
a subsequent read-only poll. The first parallel poll correctly stayed blocked
because one before bracket was absent from the scanned branch. No database or
bootstrap was reset. The successful concurrent paired read took 6.521 seconds, using thirty-second observer
age and ten required successors. The later private binding policy was already
selected at thirty seconds; no running five-second policy was widened.

This probe called only the reader and unsigned reviewer. It created no private
source claim, signature, submission attempt or data-key release. It establishes
trusted-node funding-source observation, not funded ticket lifecycle acceptance,
independent node operation or consensus verification.

## Regression verification

Final inventory: **835 tests — 140 Rust and 695 Python**, including four new
Rust and sixteen new Python tests. Validation includes:

```sh
cargo fmt --check
cargo test --locked --features live
cargo build --locked --features live --example native_ticket_worker --example ticket_read --example ticket_pilot_review --example ticket_pilot_private --example ticket_pilot_submit
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Coverage includes concurrent paired reads with SQLite access confined to the
caller thread, a common request-start time, canonical/closed native requests, invalid/private extra fields,
address routing, mixed node/role/bracket/cursor envelopes, elapsed sample age,
partial pages, removed anchors, read-profile pinning, bootstrap CLI separation,
relay failures/cancellation and a hung peer close. Existing exact-entry, reorg,
outbox, branch, submission-intent and no-retry tests remain in the full suite.

Source checksums, repository-relative links and private-key/personal-attribution
exclusion are checked before publication. Both final-head CI runs must succeed
before merge. Old forensic records and keys remain outside Git.

Host, code, clock, node views and stores remain trusted. A post-sample chain
change can precede an effect, decoder allocation precedes output-size checking,
and resource limits can halt observation. This change adds no independent
signer isolation, global exactly-once guarantee, actual data authorization,
post-quantum protection or independent audit.
