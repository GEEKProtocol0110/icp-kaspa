# Bounded chain catch-up verification

October 19, 2026. Watcher/native scan-envelope and health update. Contracts,
compiled artifacts and custody parameters are unchanged. No funded transaction
or independently hosted service was used for this change.

## Checks

- `cargo fmt --check`: passed.
- `cargo test --locked --features live`: 59 passed.
- `python3 -m unittest discover -s tests -p 'test_*.py' -v`: 79 passed.
- Both checksum-pinned fixture compilers and the live-feature build: passed;
  compiled artifacts unchanged.
- Shell wrapper syntax, systemd unit verification and diff whitespace: passed.
- New documentation links checked; banner SVG rendered and visually inspected.
- The full suite is 138 tests; 19 new Python tests are in
  `tests/test_chain_batches.py`.

The new tests cover block/transaction budgets without splitting a block;
oversized later-block preflight; incomplete, duplicate and unordered pages;
removal-budget refusal; atomic reorg undo before the first new batch;
removal-only catch-up; committed-prefix restart with preserved outbox bytes;
later semantic failure; server-truncated pages and backlog health; empty-page
reconciliation/no-progress refusal; missing targets; stale cursors and wrong
networks; exact live-outpoint checks during catch-up; original observation
timestamps; invalid budgets; bounded restart-safe log cursors; and broken-stream
failure without acknowledging unwritten events.

## Design basis

The pinned rusty-kaspa commit's
`rpc/service/src/service.rs::get_virtual_chain_from_block_v2_call` truncates
chain results internally and exposes no `hasMore` flag. The native CLI samples
`get_block_dag_info().sink` before the scan and returns that target. Local
processing tracks whether this target was reached as well as remaining blocks.
No claim of being current is derived solely from an empty local queue.

Every committed batch saves its cursor and scan progress atomically. Recovery
reconciliation runs afterward, using the existing live exact-UTXO guard and
durable signed outbox. A sampled target is an observation, not finality; a
concurrent reorganization may displace it. An empty response with an unreached
target stops for reconciliation instead of looping or reporting healthy.

## Limits and upgrade

This verifies synthetic accepted-chain processing and existing native suites.
It does not establish funded-network reaction time, an induced live reorg,
production host isolation, alert delivery or an independent audit. Upgrade both
native CLIs and the Python watcher; missing scan targets fail closed.

Budgets limit local committed blocks/transactions and atomic removal count.
They do not cap the fetched RPC's bytes/memory, signing latency, recovery-candidate
count or accumulated database history. No block is split, no history is
silently dropped, and no automatic re-anchor is introduced. Malformed envelopes
fail before committing a prefix; a later invalid semantic transition can leave
earlier valid batches durable for operator review. Existing quarantine legacy
reconciliation requirements still apply. See [WATCHTOWER.md](../docs/WATCHTOWER.md).
