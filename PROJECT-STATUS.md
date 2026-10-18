# ICP checkpoint - October 18, 2026

**Status: V1 PROTECTED-RECOVERY CANDIDATE PASSES NATIVE CHECKS; V0 LIVE PROOF PRESERVED.**

## Current candidate

- Branch: feat/protected-recovery. The additive v1 contract and icp-protected
  CLI do not replace v0 or migrate its deposits.
- Recovery creates a quarantined successor covenant. Owner and recovery-trigger
  keys cannot spend that state; cold release needs a separate key and a new,
  strictly longer delay. Quarantine cannot be repeatedly recovered or rearmed.
- One explicit role file per signing command; public setup/status/descriptor and
  broadcast do not load private keys. No v0 combined-key fallback.
- Native/script, signer, CLI and controller suites pass 85 total local checks.
  See evidence/protected-verification.md and docs/PROTECTED-RECOVERY.md.
- V1 has not been funded or live tested. No new test funds were spent.
- Same-host file separation is not production signer isolation; remote/air-gapped
  signing and deployment controls remain work.

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
- Current total test balances across all session addresses: 2.80 test KAS.

## Read first

- docs/PROTECTED-RECOVERY.md and evidence/protected-verification.md for v1.

- docs/ICP-Watchtower-Live-Proof.md and evidence/watchtower-live.json.
- docs/WATCHTOWER.md for arming, exact-intent approval, dry-run/execute mode,
  durable outbox, reorg undo, bounded retries and operational limits.
- docs/ICP-Testnet-Live-Proof.md for the earlier vault lifecycle.
- docs/VAULT-SPEC.md for the limited custody threat model.

## Files and continuation

The source package excludes live private keys and operator databases. The
private session archive includes .secrets/keys.json and runtime/, including
runtime/watchtower-pilot/watch.sqlite and the completed journals. Restore only
in a private test environment; never publish that archive or use these keys
for real funds. The repository's .gitignore excludes all of those paths.

Native CLI additions: anchor, scan HASH (VSPC v2), descriptor, prepare-initiate,
prepare-recover, broadcast PREPARED.json; status/chain reads need no private key
file. The signer still loads conventional keys on the same test host.

Use scripts/with_proxy.py with ICP_UPSTREAM_URL for this environment's normal
proxy. Exact previously resolved public TN10 endpoints are recorded in evidence.
The native runner rechecks network identity and node health before broadcasts.
Do not rerun either completed live pilot directory. Inspect and reconcile first.
The watcher is not left running as an unattended hosted service.

## Remaining work

1. Review the v1 candidate and run a fresh funded TN10 lifecycle with independent
   role files: exact intent approval, automatic quarantine recovery, explicit
   node rejection before the cold delay, later cold release and a second-node
   output check. Preserve a new journal; do not reuse v0 pilots.
2. Provide production signer isolation/transport, protect public configuration,
   and specify cold-stage rescue/key rotation before expanding custody claims.
3. Harden deployment: service restart/health, external alerts, database retention,
   deep-reorg/pruning reconciliation and bounded backlog processing.
4. Add fee estimation within the immutable cap and external adversarial review.
5. Keep data tickets, STARKs, DAG Zippers and STATIC as separately specified
   future components. No claim of mainnet or quantum-safe readiness.
