# Unsigned pilot-review verification

Date: October 20, 2026 UTC (October 19 locally). Scope: P0 public draft preparation.

- A separate native example builds unsigned issue/consume/refund previews from
  public x-only role keys, an exact asserted source and a non-secret commitment.
  Both terminal previews link to native issue ID/index 0. No key loading,
  signing, RPC, submission or live observation path is exposed.
- Eight new native tests cover exact layouts, native RPC roundtrips, empty
  signatures, operator keys, canonical schema, fixture relabeling, amount/index
  limits, commitment changes and distinct P0 domains.
- Eighteen new Python tests cover native ID recomputation, both review modes,
  receipt roundtrip/exclusive creation, unknown/private fields, numeric types,
  binary changes, no-effect commands and receipt mutation. An explicit test
  shows a checksum is not an authorization signature.
- Local native tests were compiled against the available cached dependency
  fingerprints and passed. A fresh local Cargo checkout was unavailable after
  dependency network approval was cancelled; the offline Cargo attempt could
  not fetch the pinned Kaspa source. Full locked native build/test verification
  is required through the GitHub workflow before merge.
- Full suite inventory: **624 tests (118 Rust + 506 Python)**. The Python suite,
  formatting, both contract compiler checks, public demo, documentation links
  and source checksums are checked locally. CI builds the new example before
  Python tests and runs the public fixture demo.

[Public demo](ticket-pilot-review-demo.json) contains only deliberately known
fixture keys and fabricated input data. It creates no operational key,
signature or broadcast and makes zero live RPC calls. Never fund its addresses.

The four-key fixture denylist does not prove key freshness, custody or backup.
Source entries are asserted, not observed. The unsigned output cannot prove VM
success, fee adequacy or acceptance. P0 is separate from LAB0/N0/R0. No live
journal, fresh-key private signer, source claim or controller migration is
implemented. No real data key or production-security claim is added. See
[the preparation guide](../docs/TICKET-PILOT-PREPARATION.md).
