# Release coordinator: synthetic recovery model

[Plain-English introduction](PLAIN-ENGLISH.md) · [Service design](RELEASE-SERVICE-DESIGN.md) · [Documentation](README.md)

**Local simulation with non-secret placeholders.** This tests part of the
release-service recovery design. It has no encryption, real keys, signature
verification, native transactions, RPC, transport or remote release endpoint.
Its mode is `SYNTHETIC_COORDINATOR_NO_KEYS_NO_CHAIN`.

A separate [signed coordinator lab](SIGNED-COORDINATOR-LAB.md) now extends
these transaction boundaries with real conventional permission/challenge and
revocation signatures over the same non-secret response model. The unsigned
harness described here remains a separate experiment; its fixture entry points
are not the signed lab's API. Shared protected save helpers keep signed evidence
and permanent claims in one component event without changing this model's scope.

## What it demonstrates

Imagine a service saves a delivery, crashes before replying, and starts again.
It should recover the saved delivery. It should not create a replacement or
forget the permission and budget already used. An older service copy should
also lose permission to write once recovery appoints its replacement.

[scripts/release_coordinator_model.py](../scripts/release_coordinator_model.py)
models those rules with four separate SQLite files. The authority file is
logically independent of the three component files and must remain outside
component backup/restore operations. All files still run on one trusted host.

| Store | Durable contents |
| --- | --- |
| Ledger | Exact grant contexts, permanent ticket/challenge claims, original-window charges, preparation authorization, committed response, revocations, active epochs and possible-disclosure history |
| Private fake vault | One saved non-secret response candidate per stable operation, its context/response hashes and authorizing ledger checkpoint |
| Delivery gate | Used retrieval nonces and their exact grant/request/response, writer generation, epochs, revocation sequence and deadline |
| Independent fake authority | Deployment identity, increasing writer generation, recovery readiness, clock high-water mark, halt latch and component continuity checkpoints |

The stable operation is `(service, budget, grant)`. A policy epoch, delivery
binding, writer generation or changed context does not create a second operation
for that grant. A conflicting context halts the authority. There is no candidate
or committed-response getter in the public model API; only `dispatch` returns
placeholder bytes. `status` returns accounting, flags and the committed digest.
Python attributes and direct file access are privileged, outside that API.

## Deliberately trusted inputs

`Context` accepts only bounded `model:` labels and exact integer types. It
represents an **already approved admission supplied by a trusted test harness**.
The record/cipher labels, recipient identity, delivery binding, ticket, consume
and original request are fixtures, not validated records or chain objects.

`observe` supplies two boolean fake views with a sampled logical time. Matching
fresh `True` views mean eligible inside this experiment only. A restart clears
them. `dispatch` compares the supplied original request label and response
hash, then permanently consumes a fresh nonce. That comparison is **an
authentication stub**, not a cryptographic recipient challenge or proof of key
possession. `revoke`, epoch changes and writer acquisition are trusted harness
administration, without production role authentication or recovery signoffs.

The earlier [release ledger](RELEASE-LEDGER-MODEL.md) tests model signatures,
submission intent and unknown fake-consumption outcomes. The separate
[recipient lab](RECIPIENT-ENCRYPTION-LAB.md) tests real local HPKE and signed
identity/binding operations. This coordinator does not compose or inherit their
checks. Ingestion, native issue/consume/refund, signing outboxes, cryptographic
retrieval and service attestations remain integration gates. No existing dated
anchor or real encryption key can be supplied as access authorization here.

## Save, acknowledge, then advance

1. **Recover.** Opening a writer increases the independent generation and
   disables normal work. Recovery checks every component's complete hash chain
   against the authority, reconciles exact saved but unacknowledged events,
   checks vault/ledger consistency, then enables work. Observations are cleared.
2. **Reserve.** One ledger event claims the grant, ticket and challenge and
   charges count/bytes to the original window. Duplicate exact reservations
   reconcile idempotently; they grant no new permission. Overlapping or changed
   window boundaries cannot relabel a charge. Epoch changes retain budgets.
3. **Authorize.** Current gates are checked, then an exact context-bound
   preparation authorization is saved and independently acknowledged. It is
   checked live, rather than treated as an offline bearer token.
4. **Prepare privately.** Current gates are checked again. The fake vault saves
   one randomly distinguished **non-secret** response, bound to that exact
   authorization and an acknowledged ledger checkpoint. Its own candidate
   checkpoint must be acknowledged before the next phase. A retry reuses it.
5. **Commit.** Current gates are checked again. The ledger saves the exact
   candidate and digest, permanently marks the grant used and conservatively
   sets `possible_disclosure`. Its checkpoint must be acknowledged before dispatch.
6. **Dispatch.** Current gates and exact request/response binding are checked
   under the authority lock. The gate saves and checkpoints a one-use retrieval
   nonce before returning the committed canonical bytes. New nonce retries
   return the same bytes. A lost reply never makes an old nonce reusable.

Every component journal load/save requires a live lease from its pinned
independent authority. The authority's SQLite write transaction serializes
writer changes, ledger commits, revocations and delivery authorization.
Generation checks happen at the store boundary as well as the coordinator.
A writer holding an old token or an expired boundary lease cannot continue
through these model APIs. A fresh generation cannot recall an accepted delivery.

This is not a transaction spanning all four files. Each component commits its
own event before the independent authority commits its acknowledgment. Fault
hooks exercise that gap. Hash-chained events bind mode, authority, component,
policy, sequence, prior hash, event kind and the complete state snapshot.
The witness stores exact sequence/hash acknowledgments, not secret payloads.

## Crash and restore behavior

| Situation | Result |
| --- | --- |
| Crash before a component commit | SQLite rolls back that local event; no candidate/response bytes leave |
| Component committed, acknowledgment missing | Normal operations stop; recovery checks and acknowledges the same saved history before proceeding |
| Vault candidate saved, ledger response absent | Keep it private; commit only that candidate if the original gates still hold |
| Ledger response saved, reply lost | Recover the same response, used flag and charge |
| Ledger response exists but matching vault candidate is absent/conflicting | Integrity halt; never recreate a response |
| Component backup is behind or conflicts with an acknowledged checkpoint | Integrity halt; no automatic counter/nonce reset |
| Old process or cloned older component set tries to write | Current authority fences the old token; incompatible history halts recovery |
| Revocation is accepted before commit/dispatch | Block those new operations; retain private candidate, charges and disclosure history |
| Reorg, stale sample, original expiry/window end or inactive epoch | Block preparation, commit and delivery; never refund or rewrap |
| Clock error or backward movement | Persistently halt; observed clock progress survives ordinary failed requests |

The original grant and window deadlines never extend on retry or recovery.
Revocation is idempotent and permanent. An event saved before a lost revocation
acknowledgment blocks all normal work until exact recovery; it is not discarded.
The accepted revocation sequence and consumed nonce serialize dispatch decisions.
Delivery acceptance and byte arrival remain separate events.

## Run it

From the repository root, using Python 3 and only the standard library:

```bash
python3 scripts/release_coordinator_model.py
python3 -m unittest discover -s tests -p 'test_release_coordinator_model.py' -v
```

The demo creates temporary files, reserves one fictional grant, saves a
placeholder, verifies identical-byte retries and revokes the grant. It prints
sanitized status, a response digest and zero key/RPC/broadcast counts. Random
placeholder identifiers make the digest differ between runs. A public example
is [release-coordinator-demo.json](../evidence/release-coordinator-demo.json).

The 52 new tests include separate connections, concurrent workers, stale tokens,
foreign/expired leases, copied/restored stores, lost acknowledgments, quota and
epoch continuity, revocation ordering, deadline/clock failures and actual
`os._exit` process crashes before/after the vault commit and after acknowledgment.
See the [verification record](../evidence/release-coordinator-verification.md).

## What these tests cannot establish

The authority, clock, application code, operating system, SQLite durability and
storage remain trusted. This is a serialized one-host model, without host
isolation, a protected signer/vault, production fencing provider, secure time,
administrative quorum, distributed consensus or a network delivery protocol.
An authority outage stops progress. Power-loss durability and storage-controller
behavior are not established by subprocess crashes. A process killed before a
clock observation is committed cannot preserve that uncommitted observation.

A test deliberately restores **both the authority and all component files**.
The model then accepts an already used retrieval nonce: a rolled-back witness
cannot detect its own lost history. An attacker controlling all stores/authority,
or privileged code that bypasses the modeled API, is outside this target.
Unkeyed hash chains do not authenticate an untrusted storage administrator.

Two other counterexamples accept dispatch, then revoke or change the fake chain
before bytes return. The accepted placeholder still arrives. Later operations
stop and possible-disclosure history remains; no atomic chain-to-delivery or
exactly-once network arrival is claimed. Receipts are not part of this model
and would remain claims, not proof of decryption or factual truth.

Complete snapshot journals are intentionally simple and reread for every
boundary. Retention, resource bounds and production performance are unresolved;
this is not a storage implementation to deploy behind an API. It establishes
no quantum safety, independent audit or protection for existing real data.

Next: review this recovery model and the separate
[signed coordinator lab](SIGNED-COORDINATOR-LAB.md) against the service design.
Verified delivery-key binding, response attestations and R0 wire adoption
remain review gates. Real key storage/delivery, independent enforcement and
native ticket/refund implementations need separate acceptance milestones.
