# ICP checkpoint - October 18, 2026

**Status: V1 PROTECTED RECOVERY PASSED FUNDED TESTNET-10 ACCEPTANCE.**

## Current result

- PR #1 merged the additive v1 contract and icp-protected CLI. V0 remains the
  default; existing deposits are not migrated and custody rules were not changed
  for the funded run.
- The fresh v1 pilot passed: one exact approved intent paid normally; the actual
  watcher moved the other intent into quarantine in one attempt after 236 DAA
  units, within the 600-DAA normal delay.
- The node explicitly sequence-rejected both early payouts. The exact signed
  normal and cold transactions later passed; the cold payout UTXO was accepted
  2,067 DAA units after quarantine creation (required: 1,800).
- A second TN10 node observed the quarantine output while locked and the final
  normal/cold outputs. Both vaults exited. No daemon remains running.
- All 85 offline checks pass. Read docs/ICP-Protected-Recovery-Live-Proof.md and
  evidence/protected-live.json for exact IDs, scripts, amounts and observations.
- This run spent 0.16 test KAS in eight accepted transaction fees. Total remaining
  across old and fresh session addresses: 2.64 test KAS. No real KAS was used.
- Keys are separate files and signing subprocesses on the same test host. This
  does not demonstrate OS/host isolation, an air gap, quantum safety or an audit.

## Live-tested v0 milestone

- Public repository: https://github.com/GEEKProtocol0110/icp-kaspa
- CrypTony requested public, open-source development and accepted hosting under
  Michael's account. The original implementation uses MIT; upstream licenses
  and the supplied papers retain their own terms. See NOTICE.md.
- Pre-publication source history is preserved in docs/history/pre-github.bundle;
  see docs/IMPORT.md. GitHub Actions reproduces the offline verification suite.
- The vault's initial live lifecycle passed, including an early payout rejection.
- The next live test approved one exact intent before broadcast and automatically
  recovered another unapproved intent in one attempt. The approved withdrawal
  completed after its delay. Both new vault outputs have exited.
- 54 local checks passed: 27 script tests, 3 network guards, 24 watchtower tests.
- V0 milestone balance was 2.80 test KAS before the subsequent v1 pilot.

## Read first

- docs/ICP-Protected-Recovery-Live-Proof.md and evidence/protected-live.json.

- docs/PROTECTED-RECOVERY.md and evidence/protected-verification.md for v1.

- docs/ICP-Watchtower-Live-Proof.md and evidence/watchtower-live.json.
- docs/WATCHTOWER.md for arming, exact-intent approval, dry-run/execute mode,
  durable outbox, reorg undo, bounded retries and operational limits.
- docs/ICP-Testnet-Live-Proof.md for the earlier vault lifecycle.
- docs/VAULT-SPEC.md for the limited custody threat model.

## Files and continuation

The source package excludes live private keys and operator databases. The
private session archive includes .secrets/keys.json and runtime/, including
runtime/watchtower-pilot/watch.sqlite and runtime/protected-pilot/watch.sqlite,
all fresh v1 role files and the completed journals. Restore only
in a private test environment; never publish that archive or use these keys
for real funds. The repository's .gitignore excludes all of those paths.

Native CLI additions: anchor, scan HASH (VSPC v2), descriptor, prepare-initiate,
prepare-recover, broadcast PREPARED.json; status/chain reads need no private key
file. The signer still loads conventional keys on the same test host.

Use scripts/with_proxy.py with ICP_UPSTREAM_URL for this environment's normal
proxy. Exact previously resolved public TN10 endpoints are recorded in evidence.
The native runner rechecks network identity and node health before broadcasts.
Do not rerun any completed live pilot directory. Inspect and reconcile first.
The watcher is not left running as an unattended hosted service.

## Remaining work

1. Deploy a recovery-only signer on an independent host/device with authenticated
   transport, protect public configuration, and define operator access controls.
2. Specify cold-stage rescue, key rotation and lost-key procedures before
   expanding custody claims; the final cold P2PK exit is not ongoing protection.
3. Harden service restart/health, external alerts, database retention,
   deep-reorg/pruning reconciliation and bounded backlog processing.
4. Add fee estimation within the immutable cap, broader node/network failure
   testing, and independent adversarial review.
5. Keep data tickets, STARKs, DAG Zippers and STATIC separately specified.
   There is no mainnet-readiness or quantum-safety claim.
