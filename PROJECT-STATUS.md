# ICP checkpoint - October 18, 2026

**Status: VAULT AND WATCHTOWER LIVE TESTS PASSED ON TESTNET-10.**

## Current result

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

1. Verify the public repository's GitHub Actions result and keep its checkpoint
   current. The recorded 54-check local run and funded testnet evidence remain
   distinct from CI; CI does not sign or broadcast transactions.
2. Specify and implement a protected recovery covenant rather than a plain P2PK
   recovery address; isolate recovery authority and signer from the owner role.
3. Harden deployment: service restart/health, external alerts, database retention,
   deep-reorg/pruning reconciliation and bounded backlog processing.
4. Add fee estimation within the immutable cap and external adversarial review.
5. Keep data tickets, STARKs, DAG Zippers and STATIC as separately specified
   future components. No claim of mainnet or quantum-safe readiness.
