# Private P0 preparation and recovery

ICP can now sign the reviewed P0 transaction layouts with externally supplied
private role keys and save the complete signed transaction for recovery. The
new controller is an **offline preparation experiment**. It has no node,
submission command, funding flow, real permission or data-key delivery.

In plain English: choose one outcome, save the transaction safely, and recover
the same saved transaction after a restart. If signing is interrupted before a
transaction is saved, stop and investigate rather than silently signing again.

## What is implemented

| Component | Behavior |
| --- | --- |
| Shared native builder | Public review and private signing use the same P0 layouts, commitments, IDs and fixed experimental fees |
| Private native worker | Bounded stdin/stdout `prepare` and `verify`; externally supplied key, exact role match, native Schnorr signature and script-engine verification |
| Private outbox | Full signed RPC record, asserted input entry, native ID and full native hash; recovery verifies every saved record |
| Independent authority | Trusted local SQLite serialization, writer generations, clock continuity and journal checkpoints |
| Shared source registry | One permanent claim per TN10 outpoint within the configured trusted registry; another plan or journal cannot claim it |
| Permanent branch | Consume or refund saved before terminal signing; local history cannot switch the selected branch |
| Unknown signing outcome | Durable intent remains without an outbox; later preparation refuses to re-sign |
| Public status | Mode, branch, signing flags and outbox hashes; no key or signed transaction bytes |

The native verifier requires the exact P0 layout and a minimal Schnorr
`SIG_HASH_ALL` push. It recomputes storage mass, checks the normalized full RPC
body and full native hash, then executes the native input script. An ID alone
does not identify all signature, mass and compute fields.

Public fixture plans and all four recognized fixture public keys remain
rejected by the private path. The LAB0 worker, controller and observer retain
their existing restrictions. No P0 input is relabeled as LAB0/N0/R0.

## Build and exercise safely

```sh
cargo build --locked --features live --example ticket_pilot_review --example ticket_pilot_private
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_ticket_pilot_private.py' -v
```

Tests generate ephemeral keys in temporary private files, use fabricated source
IDs and asserted entries, and delete those files afterward. They do not create
operational wallets, request funding, read a node or broadcast a transaction.
Public evidence contains no signed outbox or private key.

The Python API is `scripts/ticket_pilot_private.py`. It intentionally exposes
no operational CLI. A trusted harness must:

1. Supply and natively verify an operator-mode public review receipt.
2. Explicitly initialize a shared private claims registry once with
   `Controller.create_claims(path)`. Never reset it to resolve a conflict.
3. Open a separate journal and authority using `Controller(..., create=True)`;
   call `recover()` before any operation. Later opens use `create=False`.
4. Call `prepare('issue', asserted_entry, private_funding_key_path)`.
5. Call `choose('consume')` or `choose('refund')`, then
   `prepare('terminal', asserted_entry, private_ticket_key_path)`.
6. After interruption, reopen the same stores and run `recover()`. An existing
   outbox is reverified and reused without opening the supplied key path.

Key files must be owned regular files with no group/other permissions and
contain exactly 64 lowercase hexadecimal characters, with no newline. Symlink
key files fail. Keys go through private stdin, never process arguments or the
public review receipt. This is not an encrypted keystore, hardware signer,
process-isolation boundary or memory-zeroization guarantee.

The entry uses native UTXO JSON fields: `amount`, `scriptPublicKey`,
`blockDaaScore`, `isCoinbase` and `covenantId`. Its amount and P2PK script must
match the chosen role/source; coinbase and covenant entries fail. The input
outpoint comes from the exact public plan or native issue ID/index 0.
**These are asserted facts, not a live UTXO observation.**

## Persistence and interruption rules

The authority serializes every state transition. A signing intent and its
asserted entry are durably journaled before key access. The shared registry's
source claim is permanent, even if preparation later fails. The controller
holds a new generation-checked lease while signing and saving the outbox.
The journal uses SQLite `synchronous=FULL`; file creation is exclusive, private
and fsynced. Full saved transactions remain inside the private journal.

An interruption after the outbox commits but before acknowledgment recovers
that exact record. An interruption after intent but before outbox commit stays
`signing_started=true` with no outbox. This version has no automatic reset,
replacement, import or re-signing path for that state. Missing keys, wrong keys
and invalid entries can also leave that state. Preserve it for reconciliation;
this experiment does not make it fundable or ready for a live run.

The authority and registry must sit outside the component backup directory;
the constructor enforces that separation. The journal and authority must be
backed up separately. Restoring the journal
behind its independent checkpoints halts it. Opening a newer controller fences
older writers. A backward or uncertain trusted clock halts the authority.
Do not delete any store to clear a halt or claim.

## What the tests do not establish

- A caller with the key can invoke the native worker directly, sign both
  terminal alternatives, or construct another valid P2PK spend. Local branch
  choice is not independently enforced by the blockchain or signer hardware.
- Source exclusivity applies only to controllers sharing the same trusted
  registry. Separate registries, copied keys and external signers bypass it.
- All stores are trusted local files. Jointly restoring journal, authority and
  registry loses later branch history; an explicit counterexample test shows
  the opposite branch can then be selected. No external monotonic authority is
  implemented.
- Script-engine success does not prove that an input exists, remains unspent,
  has the asserted metadata, or will be accepted. There is no current-chain,
  depth, expiry, grant, budget or recipient authorization gate in this offline
  controller. Terminal preparation requires a saved issuance, not chain proof.
- There is no real submission or uncertain network-outcome handling here.
  Native worker failure is conservatively treated as uncertain signing. A future
  live journal needs separately durable submission intent and read-only
  reconciliation before any further effect.
- Test keys do not establish operational key freshness, custody, backup or
  restore. No funding address is approved by this work.

The separate [bound variant](TICKET-PILOT-BINDING.md) now requires fresh
[P0 observations](TICKET-PILOT-OBSERVER.md) before new preparation, with synthetic
test evidence and a distinct policy identity. This standalone offline API
retains its original behavior. The later [submission journal experiment](TICKET-PILOT-SUBMISSION.md)
adds durable attempts and reconciliation with a simulated transport; a live
TN10 adapter remains future work. Verify operational key backup/possession
before any funding request. See the [pilot sequence](TICKET-PILOT-PREPARATION.md)
and [verification record](../evidence/ticket-pilot-private-verification.md).
