# Recovery signer and supervision verification

October 19, 2026. Source implementation and deployment templates only; no service
installation, independent SSH host or funded transaction is claimed here.

- `cargo fmt --check`: passed.
- `cargo test --locked --features live`: 59 passed (3 network, 27 v0 VM,
  20 protected VM, 8 role/policy and 1 public CLI).
- `python3 -m unittest discover -s tests -p 'test_*.py'`: 46 passed,
  including 20 new recovery-service/health checks and 26 existing controller tests.
- `sh -n deploy/icp-recovery-command`: passed.
- `systemd-analyze verify deploy/*.service deploy/*.timer`: passed.

New tests cover strict recovery protocol and immutable descriptor pin, forbidden
operations/fields, malformed outpoints, independent node network/health checks,
idle/missing UTXO refusal, redirected/covenant-bearing response refusal, key-only
signing subprocess environment, strict SSH options/stdin request, durable restart
with identical signed outbox, real forced-command Python subprocess responses,
oversize/remote-command rejection, public readiness probes, stale scan and node
progress across restart, dry/local configuration, recovery retry exhaustion and
deadline, confirmation reconciliation, persistent unauthorized execution, missing
DB refusal, and independent readiness success/failure/config drift.

Transport integration substitutes an in-process SSH runner to exercise actual
request/response logic and separately starts the real Python server process with
a fake native CLI. It does not perform an SSH handshake or replace a two-host live
acceptance test. Existing native VM tests validate signed covenant transitions;
no new live native RPC acceptance run was needed for this operational change.

`docs/SIGNER-DEPLOYMENT.md` lists the outstanding host-key/account/filesystem,
network fault, dead-man alert and fresh TN10 recovery acceptance. No external
notification is configured or sent. Private key/session files remain excluded.
