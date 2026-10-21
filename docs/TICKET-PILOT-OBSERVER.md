# P0 observation through two node views

[Project home](../README.md) · [Public review](TICKET-PILOT-PREPARATION.md) · [Private preparation](TICKET-PILOT-PRIVATE.md)

The P0 observer checks whether two configured Testnet-10 node views report the
reviewed funding source as unspent, the ticket as issued and unspent, or its
exact consume/refund transaction as accepted. It is read-only. This milestone
uses synthetic tests; no funded P0 lifecycle or live P0 observation is claimed.

In plain English: before the next transaction, check the exact coins and
transaction details against two current node views. If either view is missing,
stale, inconsistent or different, the paired observation stays blocked.

## Separate profiles and checks

| Boundary | P0 behavior |
| --- | --- |
| Review | Natively reverify one exact operator-mode P0 public receipt; reject public fixture mode or relabeling |
| Projection | Recompute native ID and compare every pinned semantic field, plus input compute budget and storage mass |
| Funding source | Query funding key F; match the exact source ID/index, amount, P2PK script/version, non-coinbase flag and absent covenant |
| Ticket | Query ticket key T; require the exact issue ID/index 0 and complete matching UTXO metadata |
| Metadata | Integer creation DAA score must not be ahead of the sampled node; positive entries must agree between nodes |
| Acceptance | Reversible accepted-chain history, complete ordered pages, exact layouts and separate successor depth for issue and terminal |
| Freshness | Request-start timestamps, configured maximum age, branch-bracketed UTXO samples and new scans after reopen/failure |
| Pair | Exact same public review, policy and native build identity, distinct hostnames and separate observer database paths |
| Isolation | P0 has a distinct mode/configuration; LAB0 pair/controller APIs reject it, and cross-profile database reuse fails |

`examples/ticket_read.rs` now exposes `project-p0` alongside its existing
`project`, `scan` and `utxos` commands. The older LAB0 projection keeps its
existing treatment of compute and storage fields; the P0 projection binds them.
Neither projection independently checks signatures or consensus acceptance.
Signature bytes differ from unsigned previews and are intentionally excluded.
The private preparer's VM and full saved-outbox integrity checks remain separate.

The Python tracker reuses ordered chain rollback/depth logic while retaining
P0-specific native pins, source checks and metadata. It seals public plan,
policy, derived outpoints, endpoint, reader/reviewer hashes and database config.
Unknown funding or ticket spends block eligibility. A service journal, authority
or claims database cannot be reused as the P0 observation database.

## Observe a reviewed public plan

Build and test offline first:

```sh
cargo build --locked --features live --example ticket_read --example ticket_pilot_review
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_ticket_pilot_observer.py' -v
```

The following command performs **real read-only network calls** when supplied
real public inputs. The placeholders below are not working endpoints or block
hashes. Install the existing proxy dependency for those calls:

```sh
python3 -m pip install 'websockets==16.0'
python3 scripts/ticket_pilot_observer.py observe \
  REVIEW.json FIRST_OBSERVER.sqlite FIRST_TN10_WSS_ENDPOINT FIRST_BOOTSTRAP_HASH \
  SECOND_OBSERVER.sqlite SECOND_TN10_WSS_ENDPOINT SECOND_BOOTSTRAP_HASH
```

Each endpoint must be an explicit public
`wss://HOST/kaspa/testnet-10/wrpc/borsh` URL without credentials, query or fragment.
Each node must report synced/indexed Testnet-10 past the pinned activation.
Select a known accepted-chain bootstrap before issuance. Crossing a bootstrap
or missing required historical data fails; it is not silently reset.

The command polls both role UTXOs, scans accepted changes, prints public
observation status and closes both handles. It accepts only `observe`, never
signing, submission or key generation. Reuse the same databases, review,
endpoints and bootstrap on later polls. CLI defaults are ten selected-chain
successors and thirty seconds maximum age. These are experimental observation
settings, not calibrated economic finality. A backlog requires further polls.

For a trusted Python harness, `Tracker(..., min_successors=..., max_age=...)`
creates each configured handle. `poll_pair(first, second, clock)` performs the
read-only calls and returns a current combined report. Any failed node poll
invalidates both cached views. Direct `apply` methods are for trusted adapters
and synthetic tests; accepting a caller-supplied page is not a live RPC proof.

## What the status means

| Eligible paired state | Narrow meaning |
| --- | --- |
| `TWO_NODE_SOURCE_UNSPENT_OBSERVED` | Both current UTXO views report the exact reviewed funding entry and the scanned history has no funding spend |
| `TWO_NODE_ISSUED_UNSPENT_OBSERVED` | Both accepted views contain the exact issue with required successors and a fresh positive exact ticket entry |
| `TWO_NODE_CONSUMPTION_OBSERVED` | Both views contain the exact consume transaction with its own required successors |
| `TWO_NODE_REFUND_OBSERVED` | Both views contain the exact refund transaction with its own required successors |

Every other paired report is `TWO_NODE_GATE_BLOCKED`. A funding source has no
creation-history/depth proof here: its positive metadata is a node UTXO assertion.
DAA score is not used as a substitute for selected-chain successor depth.

Source/ticket UTXO replies are bracketed by node sink hashes. Both must occur in
order on the scanned branch. A source still reported unspent from after the
accepted issue is inconsistent. A positive sample from before that issue is
historical. The same distinction applies to ticket samples around consumption.
Reorgs revoke observations and samples; they cannot rewind private service
branch choices or outboxes because those stores are separate and unconnected.

## Trust and next work

Two hostnames do not prove independent operators or independent consensus.
Both nodes, local code, clock and observation stores remain trusted. A test
explicitly supplies a malformed signature in a fabricated accepted page and
still obtains a layout observation: projection is not a VM/consensus proof.
Node reads are sequential, not atomic, and the chain may change after the last
sample. Copied status dictionaries are not durable authorization.

The observer does not access private keys, change the private preparer's
journal, authorize a branch, reserve budget, submit a transaction or release a
data key. A later [bound variant](TICKET-PILOT-BINDING.md) enforces its current observations
before new private preparation, with synthetic test evidence.
There is no external observation anti-rollback authority or mainnet switch.
Native RPC decoding and subprocess capture happen before local output-size
checks; this is not an upstream memory-isolation boundary.

The bound variant now checks a current policy-pinned P0 pair under the private
journal lease. Next add a separate live submission-intent and reconciliation
journal. Verify fresh operational role-key backup and possession
before a funding request; execute independent consume and unused-refund pilots
only after those gates. See [the verification record](../evidence/ticket-pilot-observer-verification.md).
