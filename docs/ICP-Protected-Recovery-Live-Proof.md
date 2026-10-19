# ICP protected recovery - live testnet proof

**Passed on Kaspa testnet-10, October 18, 2026 (America/Detroit).**

The v1 watcher preserved one explicitly approved withdrawal and automatically
moved an unapproved withdrawal into the quarantined covenant. A separate cold
signature released that output only after its new delay. Both the normal and
cold payout transactions were explicitly rejected early for sequence locks,
then the exact same signed bytes were accepted later.

| Step | Transaction ID |
| --- | --- |
| Funding transfer | `21f1ebdbe2c33ac60fb694d4c57c96baf73791b7f3c84ffe8b1094d3fa307a37` |
| Approved deposit | `2530e96f0b4156c00dbd27995aa44a9ec2763cc330d6999ae66ea3a695e85a9c` |
| Unapproved-leg deposit | `bf2a9fb6284ad52fd07f36f5ce2a98364b722f690ec354b8cff9d37778c350ce` |
| Approved intent | `f7a49f773a576e7c391ba3917cf316d26b8986f316a5f209915290a33694e706` |
| Unapproved intent | `00fe1483c1eae111985a5113344064b48fad27ded051ceddc2967de47e042c6f` |
| Automatic quarantine recovery | `2af3dfd0b4db9c45f0d09785c6c4e439dec485f7034e1e9e5eca7cc0cb305dc0` |
| Approved payout | `3f0c45adeb00f8427f246cb90528f8ab0c367c17e6128f777bb58aa0111981a9` |
| Cold payout | `046a87cd97e50c67fed5acfb18ac8081b5eecedea43591fa7cbdf1d836f606ce` |

## Measured results

| Observation | Result |
| --- | --- |
| Unapproved intent accepted | DAA 600369293 |
| Quarantine recovery accepted | DAA 600369529 |
| Recovery response | 236 DAA units; one attempt; within the 600-DAA normal delay |
| Early normal payout | Explicit sequence-lock rejection; node-gate age 125 DAA |
| Normal payout accepted | UTXO DAA 600369930; age 828 DAA |
| Early cold payout | Explicit sequence-lock rejection; node-gate age 311 DAA |
| Cold payout accepted | UTXO DAA 600371596; age 2067 DAA; required 1,800 |
| Approved recipient output | 0.26 test KAS |
| Cold recipient output | 0.24 test KAS |
| Fresh owner change | 0.06 test KAS |
| Fees in this run | Eight accepted transactions at 0.02 test KAS each: 0.16 total |
| Total session funds remaining | 2.64 test KAS (legacy 2.08 + fresh 0.56) |

Early ages above are from the node gate immediately before submission; later
ages compare observed UTXO DAA scores. They are measurements, not exact-boundary
or wall-clock guarantees. Rejected early attempts paid no fee. Both deposits
were 0.30 test KAS. No idle, pending or quarantined pilot UTXO remained at exit.

## Independent node observation

A second synced, UTXO-indexed TN10 node observed the exact 0.26-test-KAS
quarantine covenant while it was still locked, then independently observed the
final 0.26 normal and 0.24 cold P2PK outputs with their exact scripts/outpoints.
Primary: vector-10.kaspa.green; secondary: muon-10.kaspa.blue, Borsh wRPC.
Both reported server 2.1.0. The secondary final virtual DAA was
600372456. These observations can change after a reorganization;
they are not an SPV proof or a finality guarantee.

## Reproducibility and limits

Code: `scripts/protected_pilot.py`, `examples/fund_protected_pilot.rs` and the
separate `icp-protected` CLI. Machine-readable public evidence is
[evidence/protected-live.json](../evidence/protected-live.json). Signature
scripts and signed outbox payloads are omitted from that public copy; complete
raw receipts, keys and the completed watcher database remain private.

The harness refuses to replace an existing journal. The bounded funding helper
pins one test-only P2PK source outpoint, amount and public key, funds only the
owner in the new public policy, and refuses an existing funding receipt. On an
ambiguous result, inspect the existing receipt and live outpoint before acting.
Never rerun this completed pilot directory.

At the time of this funded run, all 85 offline checks passed. This run
supplements native checks; it is not an independent audit, adversarial public-network reorg/outage test,
production response SLA or quantum-safety proof. Roles use separate files and
signing subprocesses on the same test host. OS/host isolation and authenticated
remote or air-gapped signing were not established by that run. The watcher at
that checkpoint did not monitor later cold releases; the pilot checked that
release explicitly.

Subsequent software added quarantine-through-cold-exit tracking and an
offline-tested recovery-only SSH kit. Those updates do not retroactively expand
this funded proof. Current tests and deployment limits are in
[PROJECT-STATUS.md](../PROJECT-STATUS.md), [WATCHTOWER.md](WATCHTOWER.md) and
[SIGNER-DEPLOYMENT.md](SIGNER-DEPLOYMENT.md). There is still no cold-stage rescue,
key rotation, permanently hosted watcher or configured external alert destination.
See [PROTECTED-RECOVERY.md](PROTECTED-RECOVERY.md)
for the surviving-authority assumptions.
