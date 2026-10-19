# Native ticket observer verification

Date: October 19, 2026. Scope: offline/synthetic native ticket observation.

- Dedicated `ticket_read` binary exposes native projection and read-only TN10
  scans/UTXO queries. The Python observer never calls the private fixture worker,
  signer, broadcast command or key-release model.
- Eight native tests recompute IDs through native RPC conversion, reject copied
  IDs with changed payloads/inputs/outputs and malformed numeric types, and show
  that signature scripts, storage mass and V1 compute budgets are outside ID
  projection. This tool does not independently validate contextual consensus.
- Thirty-eight Python tests cover exact fixture projections, positive UTXOs,
  terminal depth, reorg/reacceptance, stale clocks/scans, restarts, superseded
  handles, malformed pages, missing target coverage, host/policy disagreement,
  inconsistent UTXOs and unexpected native spends. Unexpected-spend fixtures use
  the existing known-key worker; scan bodies are fabricated, not live evidence.
- Full local suite: **562 passing tests (108 Rust + 454 Python)**.
- `cargo fmt --check`, locked live-feature tests/builds, both contract compiler
  checks, the synthetic observer demo and repository checks passed locally.
- [Public demo](native-ticket-observer-demo.json) reports issued-unspent,
  consumption, then a synthetic reorg to refund through two fabricated views.
  It makes zero RPC calls, creates zero signatures and broadcasts nothing.
- No live RPC call or broadcast was made for this milestone. No funded native
  ticket, real permission, reviewed wire adoption, controller integration,
  protected data-key delivery, production finality or quantum claim is added.

The observer stores only reversible observations. It cannot change the
controller's permanent branch, charge or saved outbox. Trusted nodes, host,
clock, configuration and storage remain assumptions. Distinct hostnames do not
establish independent operators, and the local observation store has no
independent anti-rollback witness. See [the guide](../docs/NATIVE-TICKET-OBSERVER.md).
