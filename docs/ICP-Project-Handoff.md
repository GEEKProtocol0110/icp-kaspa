# ICP continuation checkpoint

**October 19, 2026: protected-v1 quarantine custody tracking implemented.**

## Current state

Internal Command Protocol is a standalone Kaspa testnet-10 project. Use
project-level attribution and repository-relative links. The original source
uses MIT; dependencies and source papers retain their own terms. Read
NOTICE.md, AGENTS.md, PROJECT-STATUS.md and docs/VAULT-SPEC.md before changes.

The v0 vault/watchtower and additive protected-v1 lifecycle have dated funded
TN10 proofs. V1 routes recovery into a quarantine covenant. Release requires a
separate conventional cold key and a fresh, longer delay. Existing v0 deposits
are not migrated. No mainnet switch, quantum-safety finding or external audit
is provided.

The latest software extends the watcher beyond recovery confirmation:

- A recovered quarantine outpoint remains tracked, with pinned root and amount.
- An accepted cold exit must pay the descriptor's cold script within existing
  layout, value and fee bounds. The original recovery ID remains CONFIRMED.
- Cold release gets its own outpoint, amount, acceptance DAA and audit event.
- Reorganizations undo cold exits and restore quarantine. Removing recovery
  restores the pending action and its durable signed outbox.
- Health counts branch-current quarantine outputs and cold exits. Cold release
  is observed, not independently approved or signed by the watcher.
- Existing DBs or undo snapshots with untracked quarantine stop for explicit
  history reconciliation. Do not manufacture history, discard a funded DB or
  blindly rerun completed pilots.
- The fresh protected pilot now waits for the watcher's exact cold-exit
  observation as well as live UTXO observation. It was not rerun for this update.

Custody rules and compiled contract bytecode are unchanged. The controller uses
an operator-trusted indexed TN10 node and a trusted approval database. The node
enforces actual UTXO age. Fixed cold P2PK exit ends covenant protection and
later P2PK spends are not monitored by this watcher.

## Evidence and validation

- docs/ICP-Testnet-Live-Proof.md: v0 vault, early rejection, recovery and payout.
- docs/ICP-Watchtower-Live-Proof.md: approved intent and automatic recovery.
- docs/ICP-Protected-Recovery-Live-Proof.md and evidence/protected-live.json:
  funded v1 quarantine and delayed cold payout, independently observed by a
  second TN10 node. Both early signed payouts were sequence-rejected and the
  same signed transactions later passed.
- The v1 recovery took one attempt and 236 DAA units against a 600-DAA window.
  Cold exit was observed 2,067 DAA units after quarantine (required: 1,800).
  These are measured run results, not guarantees or confirmation counts.
- Previous funded runs left 2.64 test KAS across the saved session addresses.
  This update submits no transactions and does not change that recorded balance.
- New controller tests cover quarantine, cold exit, restart, reorg, rejected
  destinations/amounts/layout, durable recovery status and legacy-state refusal.
  Full verification is recorded in evidence/quarantine-verification.md.

## Signer/supervisor boundary

The offline deployment kit is in deploy/ and docs/SIGNER-DEPLOYMENT.md. It has a
recovery-only SSH forced-command endpoint, independent node/policy validation,
pinned client transport, no local signing fallback, a durable outbox, watcher
service supervision, separate readiness probe and read-only health checks.

No independent host, external alert destination or live SSH handshake has been
configured. No daemon is left running. Role files on one test host do not prove
host isolation. The cold key belongs on a separately controlled device. Keep
owner and recipient keys off watcher/signer service accounts.

## Continue from here

1. Reconcile any existing DB against the new quarantine-tracking requirements.
   Use a fresh independently journaled test session for new acceptance.
2. Install the reviewed watcher and signer on separate independently controlled
   Linux hosts once access is provided; verify SSH/public-policy pins and all
   account/filesystem restrictions.
3. Connect an approved external alert/dead-man destination; prove delivery and
   missing-heartbeat, RPC failure, signer outage and restart/outbox behavior.
4. Specify cold-stage rescue, key rotation and lost-key procedures before
   changing contracts. The current cold authority has no rescue path.
5. Harden bounded backlog processing, pruning/deep-reorg reconciliation,
   database retention and fee estimation within immutable caps.
6. Obtain independent adversarial review. Keep data tickets, STARK proofs, DAG
   Zippers and STATIC trading as separately specified future workstreams.

## Private restore and operational rules

The separately saved private session archive contains test keys, SQLite state,
signed receipts/outboxes and completed journals. Never publish it or restore it
into the public Git tree. Existing completed pilot directories must not rerun.
Inspect exact saved transaction IDs and live outpoints before retrying any
failed or ambiguous broadcast. This software update does not modify the private
archive or claim to migrate its completed checkpoints.

Use the role-specific icp-protected CLI and the scripts/with_proxy.py wrapper
when the environment needs its normal proxy. Exact historical public TN10
endpoints are recorded in evidence; every broadcast rechecks network and node
health. CI uses no live keys, no RPC and no funded session.

## Original paper review (research summary)

The paper combines covenant custody, controlled data reads and encrypted
payload/key release. Its strongest implementable idea is that a valid spending
signature need not bypass destination and delay restrictions.

Unresolved paper-level claims remain: surviving authority when all credentials
are compromised; the recovery destination's own protection; withdrawal timers
anchored to a new intent; complete fee/value/output invariants; realistic
watcher liveness; target-based quantum mining costs; derived finality bounds;
enclave memory exposure; persistent global read limits; and private decryption
key delivery. A STARK verifies specified computation but does not automatically
make key distribution private. An already disclosed key cannot be made secret
by a chain reorganization.

STATIC remains a related research reference for order batching, settlement,
liquidity and reserves. Its matching, collateral/bridge, valuation and solvency
rules require separate specifications. No STATIC implementation is present.

## Primary technical references

- https://github.com/kaspanet/kips/blob/master/kip-0017.md
- https://github.com/kaspanet/kips/blob/master/kip-0016.md
- https://github.com/kaspanet/docs/blob/main/content/docs/toccata/covenant-state.mdx
- https://docs.aws.amazon.com/enclaves/latest/user/security.html
- https://pmc.ncbi.nlm.nih.gov/articles/PMC8946996/
- https://arxiv.org/abs/2110.00878
- https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved

Research references are not audited dependencies. Exact compiler/node commits
and compiler checksums are pinned in TOOLCHAIN.json and Cargo.lock.
