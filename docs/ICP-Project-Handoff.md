# ICP continuation checkpoint

**October 19, 2026: synthetic coordinator recovery and fencing model implemented.**

For a nontechnical introduction, open [ICP in plain English](PLAIN-ENGLISH.md).
The [documentation directory](README.md) separates explanations, dated testnet
evidence, operating guides and research proposals. This handoff preserves the
engineering and operational detail needed to continue development.

## Current state

The latest module is scripts/release_coordinator_model.py. Read
[RELEASE-COORDINATOR-MODEL.md](RELEASE-COORDINATOR-MODEL.md) and
[its verification record](../evidence/release-coordinator-verification.md).
Separate ledger/vault/delivery SQLite journals pin an independent authority
identity. Active writer generations, exact acknowledgments and cross-store
response checks gate recovery and dispatch. Fifty-two new tests bring the suite
to 354 (68 Rust + 286 Python), including real process termination and restore
counterexamples. Keep the authority outside component backup/restore operations.

All responses remain non-secret placeholders. Admission, request authentication,
record/ticket/chain facts and administration are trusted synthetic fixtures;
no existing cryptographic lab or native effect is integrated. Restoring the
witness with all stores permits nonce reuse; accepted dispatch cannot recall
bytes. No production fencing provider, protected vault, remote endpoint or R0
wire/suite is selected. Next review recovery and specify/test signed R0
authorization/retrieval/revocation while responses remain synthetic. Real key
storage, independent enforcement and native ticket/refund need separate gates.
The governing proposal remains [RELEASE-SERVICE-DESIGN.md](RELEASE-SERVICE-DESIGN.md).

The earlier recipient module is scripts/recipient_lab.py. Read
[RECIPIENT-ENCRYPTION-LAB.md](RECIPIENT-ENCRYPTION-LAB.md) for exact domains,
schemas, HPKE choice and limits. It encrypts fictional messages to a pinned
X25519 delivery key after a local possession check and approver certificate;
separate Ed25519 signatures approve sending and authenticate receipt claims.
That checkpoint passed 234 Python tests; its full CI covered 302 tests (68 Rust + 234 Python).
This is a standalone local experiment, not an R0 wire adoption or remote release
service. Do not connect real keys to model grants or reuse dated anchor evidence.
Next: independent review and service-owned key, fencing/recovery and native
ticket/refund design. Current custody/live sessions remain unchanged.

The release design reference is docs/READ-TICKET-RELEASE-DRAFT.md: a proposed
service-enforced read-ticket/release model with exact recipient/key binding,
one durable response per grant, source/claim persistence, quota semantics and
separate reorg/disclosure history. scripts/release_ledger_model.py now implements
the synthetic local state/accounting experiment with fake chain observations and
non-secret placeholders. Read docs/RELEASE-LEDGER-MODEL.md and its verification
record at that checkpoint: 44 new tests; 265 total (68 Rust + 197 Python). Remote delivery is still
unimplemented; wire/crypto, ticket/refund and service-recovery gates remain.
Next specify/review those gates. Do not attach real keys or native broadcast
adapters to the model. Snapshot copies are not fenced; an observation cannot
prevent a later reorg from preceding dispatch. Both are explicit test limits.

Read docs/SECURITY-TARGET.md first for the current compromise matrix, source
paper mapping and unresolved next-generation design gates. The broader direction
includes institutional custody and controlled access to encrypted off-chain
data. A local encrypted manifest/receipt experiment is now in scripts/transfer_lab.py
and docs/TRANSFER-LAB.md. On-chain data tickets, proof enforcement and protected
key delivery remain unimplemented. Block rate alone
is not evidence of application capacity or exclusive feasibility.

The companion scripts/transfer_anchor.py now tracks an exact signed-transfer
payload/transaction ID in trusted-node accepted-chain scans. Its separate DB
retains reorg history and pins policy/bootstrap/observation settings; restart,
RPC failure, stale data or catch-up backlog prevent usable status. Read
docs/TRANSFER-ANCHOR.md. The original public demo remains synthetic. The later
funded pilot paid 0.02 test KAS, returned the remainder to its funding key and
observed the exact anchor on two distinct endpoints with 29/20 selected-chain
successors. Read docs/ICP-Transfer-Anchor-Live-Proof.md and the pilot runbook.
No key release or receiver acceptance rule changed. Unknown outcomes resume
through the read-only observe command; never replace an unreconciled anchor.

Internal Command Protocol is a standalone Kaspa testnet-10 project. Use
project-level attribution and repository-relative links. The original source
uses MIT; dependencies and source papers retain their own terms. Read
NOTICE.md, AGENTS.md, PROJECT-STATUS.md and docs/VAULT-SPEC.md before changes.

The v0 vault/watchtower and additive protected-v1 lifecycle have dated funded
TN10 proofs. V1 routes recovery into a quarantine covenant. Release requires a
separate conventional cold key and a fresh, longer delay. Existing v0 deposits
are not migrated. No mainnet switch, quantum-safety finding or external audit
is provided.

The watcher retains custody observations beyond recovery confirmation:

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

The latest catch-up update adds bounded local accepted-block/transaction
batches, atomic budgeted removals, and recovery checks between commits. Native
scans now carry a sampled sink target; a drained server page without that target
remains CHAIN_BACKLOG. Cursor/progress commits and signed outboxes survive
restart. Audit stdout uses bounded at-least-once delivery. Rebuild native CLIs
and Python together. RPC response bytes/memory, candidate count, signer latency,
retention and pruned/deep-reorg history remain outside those processing bounds.

README.md now presents the custody vision, evidence and roadmap with original
SVG artwork. docs/ARCHITECTURE.md and docs/QUICKSTART.md orient new contributors.

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
  Earlier verification is recorded in evidence/quarantine-verification.md.
- The catch-up checkpoint passed 138 tests (59 Rust, 79 Python), including 19 new
  batching/backlog/restart/logging tests. See evidence/chain-batching-verification.md.
- The custody-boundary checkpoint passed 141 tests (62 Rust, 79 Python). Three native tests
  verify actual terminal-output spends and a linked recovery-to-P2PK path using
  public role keys. The old covenant's destination, delay and fee constraints end
  at both normal and cold payouts. See evidence/custody-boundary-verification.md.
- The local-lab checkpoint passed 170 tests (62 Rust, 108 Python). The 29 local lab
  checks cover encrypted exchange binding, distinct roles, strict input/expiry,
  replay/restart/concurrency, receipt substitution and explicit attestation/DB
  limits. Public transcript: evidence/transfer-lab-demo.json. No new funded run.
  See evidence/transfer-lab-verification.md and install requirements-lab.txt
  before running the complete Python suite.
- The observer checkpoint covered 198 checks (62 Rust, 136 Python), including 28 anchor tests.
  All Python tests pass locally. The refreshed host lacks Cargo/rustup; required
  Rust verification runs in GitHub CI. See evidence/transfer-anchor-verification.md.
- Funded-anchor checkpoint: 221 checks (68 Rust, 153 Python). The pre-live 220-check build
  passed CI and supplied the checksummed binaries used for the live run; the
  published-evidence consistency check brings Python to 153 passing tests.
  The exact 0.24-test-KAS donor output was spent once, returning 0.22 with a
  0.02 fee. Existing custody-pilot journal contents are unchanged.

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

Resolve the security target's surviving-authority, continued-custody, rotation
and timing gates before choosing new contract behavior. The paper's stronger
all-credential/quantum claims are not established by operational tests. A literal
script-equality invariant also needs path-specific successor predicates. The
paper does not specify a recursive cold state machine. Existing funded v1
policies remain immutable; no design change is adopted by this checkpoint.

1. Reconcile any existing DB against the new quarantine-tracking requirements.
   Use a fresh independently journaled test session for new acceptance.
2. Install the reviewed watcher and signer on separate independently controlled
   Linux hosts once access is provided; verify SSH/public-policy pins and all
   account/filesystem restrictions.
3. Connect an approved external alert/dead-man destination; prove delivery and
   missing-heartbeat, RPC failure, signer outage and restart/outbox behavior.
4. Specify cold-stage rescue, key rotation and lost-key procedures before
   changing contracts. The current cold authority has no rescue path.
5. Validate catch-up behavior in a fresh TN10 acceptance session. Harden RPC
   resource limits, pruning/deep-reorg reconciliation, database retention and
   fee estimation within immutable caps.
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
