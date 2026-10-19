# Read-only native ticket observation

[Project home](../README.md) · [Fixture controller](NATIVE-TICKET-CONTROLLER.md) · [Native lab](NATIVE-TICKET-LAB.md)

The observer answers a narrow question: do trusted TN10 node views report the
exact fixture ticket as created, consumed or refunded? It never signs, submits a
transaction, changes the controller's permanent history or delivers a data key.
This milestone is verified with synthetic scans, not a live native ticket.

```bash
cargo build --locked --features live --example ticket_read --example native_ticket_worker
python3 scripts/native_ticket_observer.py
python3 -m unittest discover -s tests -p 'test_native_ticket_observer.py' -v
```

These commands run offline. The no-argument demo uses temporary databases,
fabricated full RPC bodies and known native fixture IDs. Its endpoints end in
`.invalid`; it performs zero RPC calls, signatures or broadcasts. Tests also
use the existing known-key fixture worker to construct unexpected native spends.
Never fund public fixture addresses. See the [public demo](../evidence/native-ticket-observer-demo.json)
and [verification record](../evidence/native-ticket-observer-verification.md).

## What is checked

| Boundary | Implemented check |
| --- | --- |
| Native adapter | `ticket_read` offers only `project`, `scan HASH` and `utxos PUBLIC_KEY`; no key loading or effect command |
| Transaction identity | Convert RPC data through the pinned native Kaspa types and recompute its ID; copied verbose IDs over changed bodies fail |
| Pinned semantics | Exact version, input outpoints/sequences, output amounts/scripts/covenants, payload, lock time, gas and subnetwork |
| Issuance | Exact issue layout plus a positive exact ticket UTXO sample; absence of a spend alone is insufficient |
| Consumption/refund | Exact separately pinned terminal transaction; unknown funding/ticket spends block eligible status |
| Branch history | Ordered accepted-chain blocks, tip-first removals, atomic page changes and successor depth for issue and terminal separately |
| Freshness | Local request-start timestamps, maximum age, monotonic clock continuity, full target catch-up and fresh scans on a new handle |
| Paired status | Matching eligible state and pins/policy from distinct hostnames and database paths |

A tracker is pinned to three public native fixture summaries, one endpoint,
one bootstrap block, its reader binary hash and observation policy. Choose a
bootstrap before issuance; a removal through it requires new reviewed history,
not silent reset. Default depth is ten selected-chain successors and default age
is thirty seconds. These experimental settings are not calibrated economic
finality or security guarantees. DAA score is not substituted for depth.

The Python `Reader` wraps the separate native binary and pins its hash. Network
methods use the existing TLS proxy, explicit public TN10 endpoints and synced,
indexed, activation-aware network guards. Calls have timeouts and local page,
transaction and reply-size checks. Native RPC decoding and subprocess capture
occur before the Python reply-size check; this is not an upstream memory bound.
The binary relies on the configured node for acceptance and UTXO validity.

## Samples and reorganizations

`poll()` requests UTXOs first, bracketed by node sink samples, then scans accepted
chain changes. The UTXO sample must be fresh and both sink hashes must appear in
order on the scanned branch. A positive sample predating issuance cannot report
an unspent ticket. A positive sample starting after accepted consumption is an
inconsistent view. A positive sample before a later spend is historical: the
later accepted spend determines the chain observation. The two reads are not an
atomic snapshot. Missing or forked samples block unspent status.

Reorganizations delete reversible block events and recalculate current state
and depth. Removing consumption can return to issuance, with a new UTXO sample
required. Removing issuance clears that observation; reacceptance starts depth
over. A failed scan/poll clears cached readiness. Opening a tracker requires a
fresh scan and UTXO sample, and supersedes older handles. Backward local clock
movement latches a halt rather than extending freshness.

Use these databases only for chain observations. They do not contain or rewind
service branch choices, charges, signing history or outboxes. The observer is
not connected to the fixture controller's `FakeNode` model or any release gate.

## Trust and remaining work

These are revocable trusted-node observations. Distinct hostnames do not prove
independent operators. Neither native ID recomputation nor node agreement
independently verifies consensus, signatures, permissions or real-world truth.
Transaction IDs exclude signature scripts, storage mass and V1 compute budgets;
accepted semantic projection is separate from complete saved-outbox integrity.
The projection tool does not run contextual VM/UTXO validation.

Local code, the clock, fixture pins, node configuration and observation storage
are trusted. There is no independent database anti-rollback witness here, and
this observer does not create authorization. No live ticket lifecycle, reviewed
N0/R0 wire adoption, independently enforced signing or protected key delivery is
established. Next test an explicit observer/controller boundary with synthetic
records while retaining permanent service history through chain rollbacks.
