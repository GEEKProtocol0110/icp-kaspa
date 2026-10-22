# Preparing a fresh-key TN10 ticket pilot

[Project home](../README.md) · [Fixture integration](NATIVE-TICKET-BINDING.md) · [Native design](NATIVE-TICKET-DESIGN.md)

The first preparation tool builds **unsigned native transaction previews** from
public role keys and an exact proposed source. It does not generate operational
keys, inspect a node, sign, submit, claim an outpoint or authorize funding.
The live signing/journal path remains unimplemented. No funding is requested.

```bash
cargo build --locked --features live --example ticket_pilot_review --example ticket_read
python3 scripts/ticket_pilot_review.py
python3 -m unittest discover -s tests -p 'test_ticket_pilot_review.py' -v
```

The no-argument demo uses the known public fixture keys and fabricated source.
Its mode says `PUBLIC_P0_FIXTURE_NEVER_FUND_NO_LIVE_PROOF`. Never fund addresses
in [that demo](../evidence/ticket-pilot-review-demo.json).

## Public review format P0

This is a separate `icp-ticket-pilot-review-p0` profile, not adoption of the
proposed N0/R0 protocol. Its evidence digest is a supplied non-secret commitment,
not a verified permission or record. The exact closed JSON fields are:

| Field | Required value |
| --- | --- |
| `namespace`, `network` | `icp-ticket-pilot-review-p0`, `testnet-10` |
| `purpose` | `operator-unsigned-review` for an operator draft; the distinct `public-fixture-never-fund` mode accepts only the fixed native fixture roles/source/nonce |
| `run_nonce` | Nonzero 32-byte lowercase hex; operator reviews reject the published fixture nonce |
| `evidence_digest` | 32-byte lowercase hex containing only a non-secret commitment |
| `funding_key`, `ticket_key`, `return_key` | Three distinct valid x-only native public keys; no seed/private/approval fields |
| `source` | Exactly `transaction_id` (32-byte lowercase hex), `index` (u32 integer), `amount` (integer sompi in the range below) |

The native decoder requires canonical sorted compact ASCII JSON, at most 16,384
bytes, with no unknown/duplicate fields, alternate numeric encodings or trailing
data. The Python command accepts a public JSON file, rejects duplicate fields
and canonicalizes it before native validation. Receipt files are bounded too.

Operator mode rejects the four published native/protected fixture public keys,
zero/fabricated fixture sources and the fixture nonce. This denylist cannot
prove a key is fresh, privately held or backed up. Other publicly known keys
may exist. Private-key possession and independent backup need later checks.
Never put secrets in digest or nonce fields: a closed schema cannot recognize
whether arbitrary hex bytes contain a secret.

The review uses the pinned native Kaspa transaction/address/mass APIs:

| Layout | Exact preview |
| --- | --- |
| Source | One asserted non-coinbase, covenant-free P2PK outpoint for funding key F, amount 24,000,000–100,000,000 sompi; its actual existence/script/age is not observed |
| Issue | One input, output 0 = 12,000,000 to T; output 1 = source minus 14,000,000 to F |
| Consume | Exact issue ID/index 0; one output = 10,000,000 to R |
| Refund | Same ticket outpoint and return amount; different commitment and native ID |
| Shared fields | Version 1, native subnetwork, gas/locktime/sequence 0, input compute budget 100, fee 2,000,000 per transaction, empty signature scripts |
| Budget | At most 4,000,000 sompi for issue plus **one** terminal spend; prior funding and later transfers are excluded |

Review digest = SHA-256 of `icp/ticket-pilot-review/p0\0` plus canonical plan.
Issue payload = `ICP-RT-ISSUE-TN10-P0\0` plus the raw review digest. For each
terminal action, hash `icp/ticket-pilot-review/p0/<action>\0` plus canonical
`{index:0, issue_id:<native issue ID>, review_id:<digest>}` and append that raw
hash to `ICP-RT-<ACTION>-TN10-P0\0`. Here `\0` denotes one NUL byte.
Native IDs are calculated by the library, not by this application hash.

Both alternative terminal previews are unsigned. They do not authorize two
spends. The future journal must select one permanent branch before any terminal
signing. P2PK itself does not enforce that service rule, expiry or permission.
Storage mass is calculated from asserted entries; VM, UTXO context, fee adequacy,
standardness and node acceptance are not established by an unsigned preview.

## Save and verify a public draft

After obtaining the actual public role keys and exact proposed source:

```bash
python3 scripts/ticket_pilot_review.py review PUBLIC_PLAN.json NEW_REVIEW.json
python3 scripts/ticket_pilot_review.py verify NEW_REVIEW.json
```

The output mode is always `UNSIGNED_P0_REVIEW_NOT_FUNDING_AUTHORIZATION`.
Creation is exclusive and fsynced. Verification checks the public checksum and
recomputes every preview through the pinned local binary. The checksum is not
an approval signature: anyone can create a different valid draft. A changed
plan/receipt requires renewed review; this file is not a durable submission
journal, grant, source claim, signed outbox or evidence of acceptance.

## Concrete pilot sequence and remaining gates

1. The [private offline preparer/journal](TICKET-PILOT-PRIVATE.md) now covers
   signing recovery, source claims and permanent branch choice with the fixture
   restrictions intact. The separate [P0 observer](TICKET-PILOT-OBSERVER.md) now
   checks node views, and the [bound variant](TICKET-PILOT-BINDING.md) gates new
   preparation with synthetic test evidence. The [submission journal experiment](TICKET-PILOT-SUBMISSION.md)
   now records attempts and reconciles simulated sends without retrying.
   The separate [native adapter](TICKET-PILOT-LIVE.md) now implements TN10
   submission capability with offline evidence. Ambiguous attempts must reconcile
   without replacement; a funded P0 lifecycle remains to be demonstrated.
2. Generate separate fresh F/T/R roles for each run, back up their private key
   files and verify possession/restore before publishing a funding request.
   The later [test-key setup helper](TICKET-PILOT-KEYS.md) implements this
   offline check; its archive must also be preserved in durable private storage.
   No operational keys or funding addresses were generated in this milestone.
3. Use two independent lifecycles: one consumes a ticket; the other refunds an
   unused ticket. They need distinct sources and run nonces. The combined
   issue-plus-terminal fee ceiling is 8,000,000 sompi, excluding funding.
4. Before signing, inspect each exact source through both pinned TN10 nodes:
   synced/indexed network/activation, amount, script/version, non-coinbase and
   no covenant binding. Pin the source, full public review and native binary.
5. Review one exact authorized action, run the native VM with the actual entry,
   fsync the full signed transaction before intent, then make at most one
   authorized submission. A reply is not confirmation. Reconcile acceptance
   through both observers with their exact layouts, freshness and depth policy.
6. Publish only dated public transaction/scan facts and measured results.
   Preserve private journals, keys, outboxes and backups outside Git. Synthetic
   reorgs remain synthetic tests; no manufactured fixture is live evidence.

The existing fixture observer/controller remains tied to LAB0. P0 has its own
[read-only observer](TICKET-PILOT-OBSERVER.md), tested with synthetic data, and a distinct
[private-controller binding](TICKET-PILOT-BINDING.md). Do not feed P0 previews into a
fixture database or silently change its policy.
No real authorization, data-key delivery, independent signer enforcement,
production finality or quantum-safety result is claimed. See the
[verification record](../evidence/ticket-pilot-review-verification.md).
