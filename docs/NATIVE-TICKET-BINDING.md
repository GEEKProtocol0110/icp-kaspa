# Connecting ticket observations to fixture recovery

[Project home](../README.md) · [Observer](NATIVE-TICKET-OBSERVER.md) · [Controller](NATIVE-TICKET-CONTROLLER.md)

The observer-bound controller connects the existing native transaction checker
to the persistent fixture lifecycle. New branch choices, terminal signing and
synthetic submission require current matching unspent-ticket observations.
Reorganizations can block progress but cannot erase the chosen branch, its
charge, a saved signed outbox or an earlier submission attempt.

```bash
cargo build --locked --features live --example native_ticket_worker --example ticket_read
python3 scripts/native_ticket_binding.py
python3 -m unittest discover -s tests -p 'test_native_ticket_binding.py' -v
```

This is an offline integration experiment. Known public keys and fabricated
inputs remain mandatory. The helper uses `.invalid` endpoint names and synthetic
full RPC pages; it makes no live calls or broadcasts. The only submission method
is the existing exact `FakeNode` local effect. No real permission or data key is
connected. Never fund fixture addresses.

## Checks at the boundary

| Boundary | Implemented behavior |
| --- | --- |
| Potential outcomes | Native `pin` operation builds unsigned IDs/layouts without signing either terminal branch; it makes no VM or full-outbox-hash claim |
| Store identity | Controller policy commits the observer pair, native reader hash, exact plans/semantic pins, endpoints, bootstrap, depth/age and separate database paths |
| Reconciliation | Read two exact tracker objects now; reject copied status dictionaries and fake acceptance maps |
| New branch/signing | Require reconciled original issuance, exact unspent ticket, sufficient successors and fresh chain/UTXO samples from both pinned hosts |
| New synthetic attempt | Recheck before intent and in the final serialized lease; saved uncertainty remains reconcile-only |
| Terminal history | Reconcile only the exact selected native semantics after durable intent, with their own successor depth |
| Restart | Clear readiness and handle acknowledgments; require new scans/UTXO samples and explicit reconciliation before new work |
| Reorg or observation restore | Change reversible facts only; preserve permanent attempts, branch, charge and private signed bytes |

The five-second controller freshness limit applies in addition to the observer's
own age policy. Both the chain request and positive UTXO sample must fit that
limit before a new action. The controller resamples its trusted clock after
record verification and when the observation read finishes; a slow read cannot
extend freshness or a deadline. New observer handles require reconciliation even if
they already have current scans. Controller recovery also clears observations.

Unsigned pins are not approvals or signed transactions. The private fixture
worker verifies complete saved native records on load. Chain observation checks
the native ID-bound projection; signature scripts, storage mass and V1 compute
budgets are outside that projection. Neither comparison replaces the other.
Pinned plans still contain invented authorization/evidence digests.

`native_ticket_binding.Controller` is separate from the original fake-map
controller. Its policy identity prevents opening these stores through the
legacy controller. Configuration changes and migrations are explicit future
work; never delete original stores or replace a pinned binary to bypass a
mismatch. Controller/authority backup directories must exclude observer stores.

A current negative result does not change an earlier `OBSERVED` attempt back to
unsubmitted. That field records irreversible service history. New work checks
the trackers again rather than using the historical flag as current permission.
Returning an existing saved transaction summary remains historical inspection;
it does not sign again or permit an additional effect.

## Limits and next work

Nodes, local code, configuration, clock and storage are trusted. Different
hostnames do not prove independent operators. Direct known-key worker calls
still bypass controller policy; no independent signer enforcement is supplied.
Restoring the trusted authority with service history can still lose that history.
The observation store itself has no independent anti-rollback witness.

There is no atomic transaction spanning a chain sample and a later signature or
effect. A counterexample changes the chain after the final sample and the local
fake effect still occurs. No prior signature or disclosed bytes can be recalled.
This experiment delivers no data key and proves no live native ticket lifecycle.

The separate [P0 preparation tool](TICKET-PILOT-PREPARATION.md) now builds
unsigned public-input previews and documents that pilot plan. Next implement a
private preparer/journal and explicit P0 observation support; fixture guards and
independent signing/authorization review remain necessary before funded use.
See the [public demo](../evidence/native-ticket-binding-demo.json) and
[verification record](../evidence/native-ticket-binding-verification.md).
