# Private P0 preparation verification

Date: October 20, 2026 UTC. Scope: offline private signing and recovery only.

- The unsigned reviewer and private worker share the exact P0 builder. The
  existing public fixture review is unchanged. The private worker rejects
  fixture mode/keys and exposes only bounded private prepare/verify commands.
- Five new Rust tests cover every action's native signature/VM check and
  unsigned ID agreement; changed mass, output, full hash, signature and action;
  wrong role/entry/coinbase/fixture mode; and private canonical input/effect
  command rejection.
- Twenty-eight new Python tests cover independent consume/refund preparations,
  private key files, unknown signing outcomes, lost acknowledgments, permanent
  branch selection, exact outbox recovery, source exclusivity, generation
  fencing, clock rollback, component restore, altered binaries/reviews and
  native signature/mass/compute/output/action mutation.
- An explicit counterexample restores all trusted stores together and then
  chooses the other terminal branch. This demonstrates the trusted local
  continuity limit; no external monotonic state is claimed.
- Inventory: **657 tests (123 Rust + 534 Python)**. The changed native examples'
  13 tests run locally against matching cached dependency fingerprints. Full
  local locked Cargo testing cannot resolve the unavailable pinned Kaspa source
  checkout in offline mode. Clean-source locked Cargo build/test remains a
  mandatory GitHub CI gate before merge.
- Local checks include all Python tests, Rust formatting, both contract
  compilers, unchanged public review demo, documentation links and source
  checksums. CI explicitly builds the private worker before the Python suite.

Test signatures use ephemeral temporary keys and fabricated inputs. No
operational key bundle, funding request, live RPC, funded P0 ticket or broadcast
was created. No private key or signed outbox is included in this evidence.

The supplied entry is asserted, not observed. Ordinary P2PK and direct worker
access bypass the Python controller's policy. Independent trusted authority and
shared-registry continuity are assumptions. No live authorization, data-key
release, quantum protection, audit completion or production claim is added.
See [the private preparation guide](../docs/TICKET-PILOT-PRIVATE.md).
