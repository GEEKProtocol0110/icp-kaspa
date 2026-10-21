# P0 observations before private preparation

[Project home](../README.md) · [P0 observer](TICKET-PILOT-OBSERVER.md) · [Private journal](TICKET-PILOT-PRIVATE.md)

A separate controller variant now requires current two-node P0 observations
before reserving a new signing attempt, accessing a key and invoking the private
native signer. Missing, stale, conflicting or mismatched evidence blocks new
preparation. Tests use fabricated node pages and temporary unfunded role keys.
No live P0 run, submission or data-key release is added.

In plain English: check the exact coins before making a new transaction, but
keep a saved transaction recoverable even when the network is unavailable.

## Gates and permanent history

| Operation | Required observation or behavior |
| --- | --- |
| New issue preparation | Both nodes currently report the exact reviewed source unspent; the supplied signing entry matches their complete metadata |
| New consume/refund choice | Saved issue outbox plus both nodes reporting the exact issued ticket unspent with required successor depth |
| New terminal preparation | Existing permanent choice plus the same current unspent-ticket check and exact signing-entry metadata |
| Existing saved outbox | Native reverify and return the same saved record without key access or a new signature; no fresh eligibility is inferred |
| Existing branch choice | Preserve it; reorgs and failed observations cannot switch consume to refund or undo history |
| Started signing without an outbox | Keep the unknown outcome; no automatic reset, retry or replacement |
| Recovery | Verify private journal/authority history, invalidate observer readiness and require fresh scans plus explicit reconciliation before new work |

The existing standalone private controller remains an offline experiment. The
new variant has a different policy identity containing a hash of the complete
observation-pair descriptor. Offline and observation-bound journals cannot be
opened interchangeably. The source-claim registry remains shared and permanent
across the two variants. No existing journal is silently migrated.

## Binding and freshness

`scripts/ticket_pilot_binding.py` accepts exactly two P0 `Tracker` instances,
not copied status dictionaries, LAB0 trackers or fake acceptance maps. The pair
pins the complete public review, node endpoints, bootstrap hashes, database
paths, native build/reviewer identities, derived outpoints, depth/age policy and
binding freshness. Both trackers must agree on the same P0 review/policy/build.
Their observation databases must be outside the component, authority and claims
backup directories.

Default binding freshness is **five seconds**, with a closed configurable range
of 1–30 seconds. Each tracker's own age/depth policy still applies. Both the
accepted-chain sample and positive UTXO sample must remain fresh at the end of
the gate read. This is an experimental local freshness limit, not finality or a
network availability guarantee.

The controller verifies saved native records before sampling the authoritative
clock. It resamples after reading both tracker statuses and rechecks after the
private key file is read. Slow record verification, observation reads or key
I/O cannot rely on the earlier lease-entry time.

A durable signing intent is saved before key access. After that reservation,
the controller obtains a new generation-checked lease and checks eligibility
again. If evidence expires or a reorg appears in that interval, it does not
call the signer. The signing intent remains uncertain and cannot be retried
automatically, even when fresh observations later return.

## Trusted harness sequence

```sh
cargo build --locked --features live --example ticket_read --example ticket_pilot_review --example ticket_pilot_private
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_ticket_pilot_binding.py' -v
```

The binding exposes a Python API and no operational signing CLI. A trusted
harness should:

1. Create two separately stored P0 observers for one exact operator public
   review and construct `Pair(first, second, freshness=5)`.
2. Open the distinct `ticket_pilot_binding.Controller(..., observations=pair)`
   with its private component, independent authority and shared claims stores.
3. Run `recover()`. This invalidates cached observer readiness and any previous
   in-memory observer reconciliation.
4. Refresh both observers, then call `reconcile_observations()` under the
   controller's lease. For real read-only calls, use the observer's existing
   `poll_pair`; direct `apply` methods remain trusted harness/test inputs.
5. Use `prepare('issue', exact_observed_entry, private_funding_key_path)` only
   with current source evidence. Preparation reserves and saves a signed
   outbox; it does not broadcast.
6. Once both views report exact accepted issuance and a positive ticket UTXO,
   refresh/reconcile, select one branch and prepare its terminal transaction.

A new observer handle supersedes the old handle. Reopen the pair with the same
pinned descriptor, rescan and reconcile before new work. Service recovery never
imports an old positive observation as permission. The configured observer
handles/stores must remain available for identity checks; historical outbox
recovery needs no fresh node eligibility or key file.

Public status contains only the binding mode, policy hash, permanent branch,
signing flags and outbox hashes. Its scope is explicitly
`HISTORICAL_OUTBOX_NOT_CURRENT_CHAIN_PROOF`. It is not a current chain report,
approval receipt or disclosure authorization. Keys and complete signed outboxes
remain private and excluded from Git.

## Limits and next work

- Node reports, local code, clock, storage and the shared claim registry remain
  trusted. Distinct hostnames do not establish independent node operators.
  Pair reconciliation is not cryptographic permission, grant validation,
  recipient verification, quota accounting or a funding approval.
- The two node reads and signing are not atomic. A counterexample changes an
  observer after the final sample but before native signing; the signature is
  still created and its outbox saved. Already signed bytes cannot be recalled.
- A caller holding the role key can use the standalone controller or native
  worker directly. P2PK consensus does not enforce this local observation gate,
  branch choice or service expiry. Independent signer isolation is future work.
- Joint restore of all trusted private stores can lose later branch history;
  the earlier explicit counterexample still applies. Observation restore cannot
  fix or erase private checkpoint/outbox history.
- There is no network submission command or live submission journal here.
  Signing intent is not broadcast intent; acceptance observations alone do not
  establish that a locally authorized submission occurred.

Next implement separately durable submission intent, one authorized effect and
read-only reconciliation for unknown network outcomes. Verify operational role
key backup/possession before funding independent consume and unused-refund
Testnet-10 pilots. See [verification](../evidence/ticket-pilot-binding-verification.md).
