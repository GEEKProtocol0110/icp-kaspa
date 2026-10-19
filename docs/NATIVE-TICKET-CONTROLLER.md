# Persistent native fixture controller

[Project home](../README.md) · [Native transaction lab](NATIVE-TICKET-LAB.md) · [Design](NATIVE-TICKET-DESIGN.md)

The controller saves one native fixture lifecycle: its original issuance,
one permanent consumption-or-refund choice, exact signed outboxes and submission
attempts. Crashes and restarts recover the saved transaction rather than signing
a replacement. It has **no RPC, funded input, real permission or data key**.

```bash
cargo build --locked --features live --example native_ticket_worker
python3 scripts/native_ticket_controller.py
python3 -m unittest discover -s tests -p 'test_native_ticket_controller.py' -v
```

The no-argument demo creates temporary private databases, uses the known
fabricated native fixture, loses a synthetic reply and recovers the same outbox.
It prints hashes and decisions only. [Public demo](../evidence/native-ticket-controller-demo.json)
and [verification](../evidence/native-ticket-controller-verification.md) contain
no signed outbox or operational secret. Never fund known fixture addresses.

## Persistence and order

| Boundary | Implemented fixture behavior |
| --- | --- |
| Initialization | Exclusive private file creation; policy pins the exact issue plan and native worker binary hash; partial/missing stores are not reset |
| Recovery | Acquire a new writer generation; verify journal/checkpoint history, native records and irreversible transitions; clear observation caches |
| Issue preparation | Save the complete native serialized transaction before reporting its public summary |
| Terminal choice | Require reconciled fresh synthetic issuance views; save choice and consume charge or unused closure before any terminal signing |
| Terminal preparation | Sign only the chosen exact plan; checkpoint the private outbox before returning metadata |
| Submission intent | Commit one attempt and continuity acknowledgment before a second enforcing lease permits one strictly local fake effect |
| Lost/unknown result | Reconcile only, even if no effect is observed; never replace, switch branch or automatically retry |

The component `ticket.sqlite` uses the existing recovery model's hash-chained
journal. A separate authority database outside its backup directory serializes
operations, fences older controller generations, tracks trusted logical clock
progress and acknowledges exact checkpoints. No cross-database atomicity is
assumed: a component commit ahead of its acknowledgment recovers that exact
history. A component restored behind the authority halts.

Every load checks native saved records and irreversible history. Records,
branch, original terminal plan and charge cannot change or disappear; attempts
cannot regress or skip intent. A missing native verifier blocks work without
discarding a saved outbox. An invalid record/history halts the authority.
Status exposes outbox hashes, branch, attempts and charge, never signed bytes.

The Rust worker has bounded private stdin/stdout operations for plan validation,
terminal planning, preparation and verification. Planning and verification do
not sign. Saved records include the complete transaction and full native hash;
strict round-trip serialization and the native lab's layout/VM checks detect
ambiguous or changed records. Its binary hash is pinned and checked before use.
A different build needs an explicit future migration procedure, not new stores.

Consume reserves one count and the original fixture ciphertext byte length in
its original window. This is one lifecycle's accounting, not a service-wide
multi-grant budget. Once reserved, expiry, fake reorg or failures never refund
that charge or permit a refund branch. Unused expiry closure must wait until
the original expiry; the revoked-closure flag is a trusted fixture input.
Returning a saved summary after expiry is historical inspection, not new signing.

## Limits and next work

`FakeNode` is an in-memory synthetic acceptance map. Both distinct views must
match the exact native ID/full hash, and cached observations expire after five
logical seconds. Restart clears them; disagreement or simulated removal blocks
new eligible work. These are not native scans, chain-depth checks or proof of
acceptance. Submission replies do not confirm anything.

All components, administration, clock and worker execution share a trusted host.
Calling the known-key native worker directly bypasses the Python controller;
independent signer enforcement is unimplemented. Restoring the authority with
the component can lose accepted branch history, as an explicit test shows.
Different independent authorities are not coordinated globally. Copied signed
bytes cannot be recalled. No production isolation or rollback resistance is claimed.

Thirty-seven Python tests and four additional native tests cover restart,
concurrent choice, real process death, partial acknowledgment, stale generations,
corruption, restore, unknown outcomes and scope counterexamples. The separate
[read-only observer](NATIVE-TICKET-OBSERVER.md) now exists, with synthetic scan
and reorg tests. The [connected variant](NATIVE-TICKET-BINDING.md) now gates new
fixture work on those observations; this original variant still uses fake maps.
A separately authorized TN10 pilot remains ahead. Real authorization, independently enforced signing, reviewed N0/R0
wire rules and protected key delivery remain separate gates.
