# Candidate protected recovery - local verification (historical)

October 18, 2026. No funded v1 transactions were submitted for that native-only milestone.
A later funded run is recorded in docs/ICP-Protected-Recovery-Live-Proof.md
and evidence/protected-live.json.
Earlier v0 transaction IDs demonstrate only the original contract's live paths.

| Suite | Checks passed |
| --- | ---: |
| Original vault native VM | 27 |
| Network/activation guards | 3 |
| Protected-v1 native VM | 20 |
| Role file and policy guards | 8 |
| Public-only CLI setup/descriptor | 1 |
| Watchtower/controller | 26 |
| Total | 85 |

Commands passed: `python3 scripts/compile.py`,
`python3 scripts/compile_protected.py --fixtures`, `cargo fmt --check`,
`cargo test --locked --features live`, and
`python3 -m unittest discover -s tests -p 'test_*.py' -v`.

The VM tests execute the actual compiled v1 bytecode under a committed compute
budget. They check all five permitted state/entry paths and reject all others,
role substitution, recovery to public-key outputs, hot-state resets, redirected
cold payout, short/disabled delays, immutable-policy replacement, repeated
quarantine recovery, extra inputs/outputs, value inflation and excessive fees.
A three-transaction chain constructed by the native builder passes the VM:
idle -> pending -> quarantine -> final cold P2PK, paying at most three caps.

File tests verify the recovery signer needs no other role file, rejects wrong
roles/public keys/networks and combined files, creates keys without overwrite,
and rejects permissive permissions and symlinks on Unix. CLI setup and public
descriptor commands work with no signer file present. File separation alone
does not provide independent-host security, encrypted key storage or air gaps.

The watcher records v1 recovery as QUARANTINED and preserves its existing
submission-versus-chain-confirmation, undo and durable-outbox behavior. It does
not sign or monitor cold releases. Native sequence success is explicitly
distinguished from a node's actual UTXO-age check.

Not established: v1 live relay acceptance/fees, node-side early-cold-release
rejection and later acceptance, real outage/reorg behavior, cold-host deployment,
production response windows, lost-key rescue, quantum safety or an independent
audit. See docs/PROTECTED-RECOVERY.md for the narrower threat model.
