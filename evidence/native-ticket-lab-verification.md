# Offline native ticket verification

October 19, 2026. ICP contributors.

[Implementation guide](../docs/NATIVE-TICKET-LAB.md) · [Public vectors](native-ticket-lab-demo.json)

Scope: native issue/consume/refund transaction layout and signature checking,
using fabricated UTXOs and known public keys. This is not live-chain evidence.

- 28 new Rust tests exercise exact linked transaction layouts, canonical closed
  fixture schemas, amount/key/source bounds, noncircular issue binding,
  incompatible admission/closure fields, native signature mutations and saved
  full-hash checks. The public vector test reproduces all three summaries.
- Explicit counterexamples show valid arbitrary P2PK controller spends and
  alternative conflicting terminal transactions. No permanent branch controller
  or real authorization enforcement is claimed.
- Tested V1 storage-mass/compute mutations preserve ID and signature hash;
  native hash and layout checks detect changes. A different valid signature
  preserves ID and VM validity but fails the original saved-hash check.
- Standard-library Python independently recomputed each published commitment
  from its complete sorted compact ASCII plan and lab action domain.
- Local required verification includes format, the complete native suite and
  Python suite: **475 tests (96 Rust + 379 Python)**. The demo runs locally and
  is included in CI. Final-head hosted verification is recorded on the PR.

No signed transaction outbox, private key, content key, plaintext, database or
session is published. The example accepts no arguments or key/RPC configuration;
it prints public fixture plans and summaries only. No RPC, funded transaction,
custody rule change, model-grant integration or real key release was added.

The SHA-256 dependency is pinned to the already-locked `sha2` 0.10.9; no existing
dependency revision changed. Native consensus/script APIs use the existing
rusty-kaspa/toolchain pins. The lab has its own namespace/prefix and does not
freeze the proposed N0/R0 authorization protocol.

Fees, mass/relay suitability and chain acceptance were not measured against a
live node. Evidence digests remain invented fixtures, and the lab deliberately
can sign both alternative terminal branches. Persistence, branch fencing,
unknown-effect reconciliation, independent enforcement, protected data-key
ownership and authenticated delivery remain unimplemented gates.
