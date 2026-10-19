# ICP checkpoint - October 19, 2026

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
- All 105 offline checks pass (59 Rust and 46 Python). Read docs/ICP-Protected-Recovery-Live-Proof.md and
  evidence/protected-live.json for exact IDs, scripts, amounts and observations.
- This run spent 0.16 test KAS in eight accepted transaction fees. Total remaining
  across old and fresh session addresses: 2.64 test KAS. No real KAS was used.
- Keys are separate files and signing subprocesses on the same test host. This
  does not demonstrate OS/host isolation, an air gap, quantum safety or an audit.

## Recovery signer and supervision kit (offline verified)

- Recovery-only SSH forced-command endpoint pins the protected-v1 descriptor,
  independently checks the live pending UTXO on TN10, and returns only a prepared
  fixed-quarantine transaction. No remote broadcast, arbitrary command or cold
  release is exposed. The client pins the SSH host key with no local fallback.
- Existing durable outbox/reorg handling remains; public native operations strip
  the signer-key environment. Private receipts can live outside read-only public
  state via ICP_PROTECTED_RECEIPT_DIR.
- Watcher service has bounded restarts. A separate signer readiness timer avoids
  blocking scans; read-only health checks report stale scans, stalled DAA, signer
  outage, dry/local mode, recovery deadlines, exhausted attempts and unauthorized
  execution. Restarted watchers preserve log cursor and DAA-progress history.
- Deployment/config templates: deploy/. Instructions and limits:
  docs/SIGNER-DEPLOYMENT.md. Verification: evidence/signer-verification.md.
- No host or SSH credentials were supplied. No independent-host installation,
  live SSH handshake, external alert delivery or new funded run was performed.
  The 2.64 test KAS balance and existing pilot receipts are unchanged.

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

1. Install and validate the reviewed signer/supervision kit on independent hosts,
   verify host/descriptor pins and permissions, wire an approved external alert
   destination, and journal fresh TN10 acceptance. No hosts are configured yet.
2. Specify cold-stage rescue, key rotation and lost-key procedures before
   expanding custody claims; the final cold P2PK exit is not ongoing protection.
3. Complete external alert acceptance, database retention,
   deep-reorg/pruning reconciliation and bounded backlog processing.
4. Add fee estimation within the immutable cap, broader node/network failure
   testing, and independent adversarial review.
5. Keep data tickets, STARKs, DAG Zippers and STATIC separately specified.
   There is no mainnet-readiness or quantum-safety claim.
