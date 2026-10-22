# Bounded P0 history catch-up

An observer that has been paused may receive a history page larger than the
relay's unchanged 8 MiB frame limit. The funded pilot encountered a 19,644,270-byte
frame and stopped before a submission intent. Repeating the same full request
could not advance its cursor. The two previously signed issuances remain saved;
the user has approved the four planned TN10 transactions and their fee ceiling.

The separate `ticket_history_catchup` example requests **full accepted history**
with a blue-score window. It reads the actual cursor and sampled sink headers,
checks their hashes, and calculates
`min_confirmation_count = max(0, sink_blue_score - start_blue_score - window)`.
The pinned node implementation strips the recent end of its bounded chain path
using that hint before loading the full accepted transactions. Supported windows
are 16, 64, 256 and 1024; smaller windows can help when a page is too large.
The hint is not a finality or exact block-count claim.

The sampled sink stays the real target. The last returned block never replaces
it. A partial page advances the existing cursor; it does not claim catch-up.
No transaction is omitted from a returned accepting block. The existing observer
checks full transaction inputs, exact relevant native bodies, duplicates, page
order, unknown spends and reverse-order reorgs. A reorg across the original
bootstrap still fails. No database, bootstrap or policy is reset or relabeled.

The helper accepts only a closed canonical public cursor/window request. It has
no role keys, UTXO query, signing or submission command. Synced/indexed activated
TN10 health is checked before and after the read, with a 25-second connection/read
budget and bounded disconnect. Existing frame/output limits remain; decoding
and capture precede the output-size check and are not hostile-node memory
isolation. A single large block, unavailable/pruned history or timeout may still
block recovery. Never remove a limit or invent completion to proceed.

## Recover history, then refresh eligibility

Stop the old live operators and preserve their current private checkpoint.
Keep all existing private journals, authorities, source claims and pinned old
binaries. Build the auxiliary example into a different target directory; do not
rebuild workers that an existing journal pins. Pin the helper and relay hashes
separately in the trusted operator gate and retain their build/source record.

For each existing observer database, use its exact original review, endpoint,
bootstrap, reader/reviewer binaries and successor/age settings:

```sh
python3 scripts/ticket_pilot_catchup.py PUBLIC_REVIEW OBSERVER_DB TN10_WSS_ENDPOINT BOOTSTRAP_HASH \
  --binary AUXILIARY_HISTORY_BINARY --reader ORIGINAL_PINNED_READER \
  --reviewer ORIGINAL_PINNED_REVIEWER --window 256 --pages 32
```

The CLI refuses a missing observer file. Opening the store supersedes older
handles; imported pages apply on the SQLite owner thread. Binary/relay changes,
wrong endpoints, profiles, windows, hints and cursors fail. The original observer
descriptor stays unchanged. The history helper is a separately reviewed trusted
recovery input, not a replacement for the normal snapshot adapter.

Each import invalidates readiness **even if its target is reached**. It supplies
no positive source/ticket UTXO sample and returns `eligibility: false`. Only the
original pinned snapshot path can restore fresh eligibility in the live harness.
Reopen/recover the original controller, poll both pinned nodes, and reconcile
their current exact entries before any already-authorized effect. Historical
reports and helper output cannot authorize a send or widen the thirty-second
policy. Any existing submission intent remains reconciliation-only, without retry.

## Evidence

The [live page probe](../evidence/ticket-history-catchup-live.json) advances four
**copies** of the existing funded observers with window 1024. It records actual
page cursors/targets and ineligible reports. Live observer stores, claims,
outboxes and private authorities were untouched by that probe. This record
establishes historical progress, not complete catch-up or ticket acceptance.

Regression tests cover historical progress without eligibility, a later normal
snapshot, native-body tampering, preserved bootstrap/reorg rules, changed pins,
invalid replies, stale handles, no progress and request-start timestamps. The
new inventory is 142 Rust + 704 Python tests. All evidence remains trusted-node
observation; actual authorization, key delivery and independent signer isolation
are separate work.
