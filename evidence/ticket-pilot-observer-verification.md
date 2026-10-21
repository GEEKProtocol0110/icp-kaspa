# P0 observation verification

Date: October 21, 2026. Scope: read-only P0 observation; synthetic node evidence.

- The native adapter's separate `project-p0` command recomputes native IDs and
  binds storage mass and input compute budgets in addition to the existing
  semantic projection. The legacy LAB0 projection remains unchanged.
- Three new Rust tests cover ID-excluded compute/storage changes, malformed
  native variant/ID data, and the explicit absence of independent signature
  verification in the observational projection.
- Thirty-four new Python tests exercise public-review recomputation and fixture
  rejection, funding-source queries, exact role/outpoint/entry metadata, node
  disagreement, separate issue/terminal successor depth, stale and forked
  samples, reorg rollback, native-body mutation, handle fencing, config/binary
  changes, profile/database separation, failed/slow polling and the read-only CLI.
- A negative test gives a malformed signature in a fabricated accepted page;
  the observer reports matching layout. This is deliberate evidence that node
  acceptance is trusted and projection is not a separate VM/consensus proof.
- Inventory: **694 tests (126 Rust + 568 Python)**. Full locked Rust tests,
  all Python tests, formatting, both contract compilers, unchanged public
  review output, existing observer/controller demos, repository links and source
  checksums are verified locally. The pinned toolchain and dependencies were
  fetched successfully for this milestone. Final-head push and PR CI remain
  mandatory merge gates.

New P0 observer tests use ephemeral public role keys and fabricated native RPC
pages. The observer performs no signing and invokes no private worker. There
was no live P0 RPC call, funded P0 run, new operational key bundle, funding
request or broadcast for this milestone. Prior live watchtower/vault evidence
remains separate from these synthetic P0 observations.

P0 signing/journal enforcement, live submission intent and reconciliation,
operational backup/possession verification, independent node-operator trust
and real authorization remain separate work. No production, quantum-security,
real-world truth or global security guarantee is established.
See [the observation guide](../docs/TICKET-PILOT-OBSERVER.md).
