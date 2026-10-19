# ICP checkpoint - October 19, 2026

**Experimental Kaspa Testnet-10 prototype.** Vault withdrawals and protected
recovery have been tested with test coins. Real data-key delivery is still being
designed.

New here? Read [ICP in plain English](docs/PLAIN-ENGLISH.md) or browse the
[documentation directory](docs/README.md). This page records the current
engineering checkpoint first, followed by earlier milestones.

| At a glance | Current position |
| --- | --- |
| Vault and recovery | Dated testnet runs and automated verification |
| Data access | Local recipient encryption, signed request checks and synthetic recovery; no remote release service |
| Automated coverage | 402 tests: 68 Rust + 334 Python |
| Next engineering work | Review signed recovery; specify delivery-key binding/response attestations, production enforcement and native ticket/refund implementations |

## Signed coordinator permission/request checkpoint

- scripts/signed_coordinator_lab.py adds a separate, strictly encoded lab format
  for approver/sender permission signatures, service challenge signatures,
  recipient admission/retrieval proofs and distinct-signer grant revocations.
  Five Ed25519 roles, service/budget and limits are pinned in the durable policy.
- Evidence and permanent nonce claims share the same checkpointed ledger or
  delivery event as the action. The response context binds actual permission
  and original signed-request digests. Recovery retains signatures, charges
  and responses, but invalidates old-generation outstanding challenges.
- The recipient helper verifies the intended permission and expected response
  digest. Signed revocation binds the exact grant/permission, next global
  sequence and unique ID; accepted revocation blocks already signed retrieval.
- 48 new tests bring the suite to 402 (68 Rust + 334 Python), including an
  actual process exit after reservation commit and before checkpoint acknowledgment.
  All Python tests pass locally; required native/build/template checks run in CI.
- Responses remain dummy values. Records, delivery binding, native ticket/chain
  facts and administration remain trusted fixtures. No HPKE integration, content
  keys, transport endpoint, production enforcement or adopted R0 wire is added.
- Counterexamples relay one copied signed request and lose an accepted signed
  revocation by restoring the authority with all stores. These remain trusted
  service/continuity boundaries, not production anti-rollback or secure transport.
- Read docs/SIGNED-COORDINATOR-LAB.md and
  evidence/signed-coordinator-verification.md. Next: review signed boundaries and
  specify/test recipient delivery-key binding plus response attestation with
  synthetic responses before separate real-key/native-ticket/remote milestones.

## Synthetic coordinator recovery checkpoint

- scripts/release_coordinator_model.py models separate ledger, private fake-vault,
  delivery journal and independent fencing/checkpoint authority stores. Normal
  work requires recovery verification and an active writer generation enforced
  at component loads/saves, with an authority identity pinned in each journal.
- Durable candidates recover as the same exact placeholder after lost replies.
  Status exposes no candidate bytes. A committed response without its matching
  vault candidate halts; a restored component behind the independent witness
  cannot silently reset claims, budget charges, revocations or retrieval nonces.
- Revocation, fake reorgs, stale samples, original deadlines and inactive epochs
  stop new release decisions without refund or replacement. Clock failures
  latch a halt. Accepted delivery cannot recall bytes already in flight.
- 52 new tests bring the suite to 354 tests (68 Rust + 286 Python), including
  actual process crashes and independent connections. Python runs locally;
  required Rust/build/template verification runs in the milestone's CI.
- This uses trusted admission/authentication/administration fixtures and boolean
  chain views. It does not integrate the earlier signed ledger or HPKE lab,
  hold keys, provide production isolation/fencing or perform native transactions.
  A counterexample restores the witness with all stores and reuses a nonce.
- Read docs/RELEASE-COORDINATOR-MODEL.md and
  evidence/release-coordinator-verification.md. Next: review recovery and the
  signed R0 authorization/retrieval/revocation contract with synthetic responses
  before separate real-key, native-ticket or remote-delivery milestones.

## Release-service design checkpoint

- docs/RELEASE-SERVICE-DESIGN.md proposes the ownership and recovery boundaries
  connecting the existing R0 draft, recipient lab and simulated grant ledger.
  It defines private per-version content keys, one stable response operation
  per grant, a private vault outbox, ledger commit and a separate delivery gate.
- Cross-store failures recover the same saved candidate/response. Revocation,
  expiry and reorgs stop eligibility without refunding quota or erasing used
  grants. Candidate encrypted key responses are treated as disclosure capabilities.
- A proposed independent authority would fence obsolete writers and acknowledge
  continuity checkpoints. Restored snapshots cannot silently reset claims,
  nonces, revocations or clock progress. Providers/enforcement are unimplemented.
- This is a design-only change. The 302-test implementation checkpoint is
  unchanged; no service, key store, remote endpoint or funded ticket was created.
  Publication is not independent security review or R0 wire/suite adoption.
- Next executable milestone: synthetic-only coordinator recovery model with
  separate fake vault, fencing/checkpoint authority and delivery gate. Keep
  responses non-secret and disconnected from real keys/native transactions.

## Local recipient-encryption lab

- scripts/recipient_lab.py uses the pinned library's HPKE implementation to
  encrypt a fictional message to a separate X25519 delivery key. Ed25519 roles
  approve the exact envelope, authenticate the sender and sign receipt claims.
- A trusted local registry checks a fresh encrypted possession challenge and
  commits an approver certificate plus used challenge atomically. Receiver
  replay receipts persist before plaintext return; concurrent connections and
  restarts preserve local claims. Databases pin policy and component role.
- The new namespace and documented wire/context choices are separate from
  lab-v0, the simulated release ledger and R0. No raw symmetric key is passed
  to the recipient caller. No RPC, transport server, native ticket or real-key
  attachment to simulated grants is implemented.
- All 234 Python tests pass locally, including 37 new cases. The full 302-test
  checkpoint runs Rust/build/template verification in GitHub CI. The demo and
  public transcript contain fictional data, public metadata and ciphertext.
- Explicit limits include ordinary one-host memory, trusted policy/clock,
  unfenced database copies, later delivery-key compromise exposing history,
  recipient copying and forgeable receipt claims by the recipient-key holder.
  No independent application audit, forward-secrecy or quantum-safety claim.
- Read docs/RECIPIENT-ENCRYPTION-LAB.md and evidence/recipient-lab-verification.md.
  Next: independent review and service-owned key/recovery design before R0
  integration or protected remote release. No funded session changed.

## Synthetic release-ledger model

- scripts/release_ledger_model.py implements the draft's local state/accounting
  experiment using a strict FakeChain adapter and non-secret response placeholders.
  It performs no RPC, native ticket preparation, encryption or content-key delivery.
- Model-specific approver/sender signatures and recipient challenges bind exact
  immutable grants. One SQLite transaction claims each grant/nonce, charges the
  fixed-window count/byte budget and saves the exact consumption plan.
- Submission intent is durable before one fake effect. Unknown/crashed attempts
  reconcile only. Responses are stored before retrieval; fresh authenticated
  retries preserve identical bytes and the original deadline/window.
- Reorgs, expiry and revocation block delivery without deleting used grants,
  response/disclosure history or quota. Clock errors/backward movement latch a
  halt. Two copied databases can still claim independently; a reorg after the
  final sample can precede dispatch. Both limits have counterexample tests.
- 44 new tests include concurrency and actual subprocess crashes around response
  commits. At that checkpoint: 265 checks (68 Rust + 197 Python). Python runs locally;
  required Rust/build/template checks run in GitHub CI on the milestone PR.
- Read docs/RELEASE-LEDGER-MODEL.md and evidence/release-ledger-model-verification.md.
  Next: review wire/recipient-delivery requirements, service fencing/recovery
  and native ticket/refund rules. No funded ticket or remote release is enabled.

## Read-ticket and key-release design draft

- docs/READ-TICKET-RELEASE-DRAFT.md specifies the proposed next experiment's
  authority and object bindings, issuance/consumption/release gates, durable
  states, service-wide accounting and adversarial acceptance cases.
- One use means one durable encrypted key-response grant, with identical-byte
  authenticated retries. It does not limit later reads/copies by a key holder.
- Reorgs revoke current eligibility but never erase a used grant, budget charge
  or possible disclosure. A trusted service ledger is separate from reversible
  chain observations; clone/restore/fencing assumptions are explicit.
- This is a proposal, not implemented enforcement. A plain P2PK ticket would
  leave policy/expiry/budget enforcement at the service. Cryptographic delivery,
  wire formats, ticket/refund transactions and stronger on-chain rules have
  explicit gates. The subsequent synthetic model is described above.
- At that design checkpoint the 221-check code and live evidence were unchanged. No test keys, data
  keys, tickets or funded transactions were created for this documentation step.

## Funded transfer anchor observed

- A fresh synthetic encrypted exchange was committed in TN10 transaction
  dce0ddf4ad0e420918c2216a85e2b179650e6a10ac7566cb60d99eee69b585f1.
  One submission spent the exact saved 0.24-test-KAS change output, returned
  0.22 test KAS to the same key and paid a fixed 0.02-test-KAS fee.
- Two distinct TLS endpoints reported the exact accepted transaction with
  29/20 selected-chain successors, then independently reported its exact new
  output as unspent. Both scans started at 2026-10-19 05:54:27 UTC.
- New native preparation and journaled pilot preserve signed bytes before
  submission, pin/claim the source, reject replacement runs and resume reads
  without signing or broadcasting. Existing custody sessions were not rerun.
- At that checkpoint: 221 checks (68 Rust + 153 Python). The pre-live 220-check
  checkpoint passed GitHub CI; the added public evidence consistency test
  passes locally with all 153 Python tests. Native sources are unchanged since
  that verified build. Final workflow results are recorded on PR #9.
- Read docs/ICP-Transfer-Anchor-Live-Proof.md, docs/TRANSFER-ANCHOR-PILOT.md
  and evidence/transfer-anchor-live.json. No protected key delivery, consensus
  proof, live reorg experiment, independent-host isolation or quantum claim.

## Original transfer commitment observer checkpoint

- scripts/transfer_anchor.py now binds the complete signed encrypted exchange
  and trusted policy to a domain-separated transaction payload commitment.
- A separate durable tracker consumes native read-only accepted-chain scans,
  pins an exact transaction ID, counts selected-chain successors, checks the
  sampled sink/freshness and undoes observations on reorgs. Restart or RPC failure
  requires another successful scan. Oversized/incomplete pages fail atomically.
- This is a trusted-node observation module, not SPV, access authorization or
  protected key delivery. The receiver is unchanged. No transfer anchor was
  broadcast; evidence/transfer-anchor-demo.json uses explicitly synthetic IDs
  and a simulated clock. No funded session was touched.
- That checkpoint covered 198 checks (62 Rust + 136 Python), including 28 new anchor
  tests. Python passes locally; required Rust checks run in GitHub CI because
  the refreshed local host has no Rust toolchain. Read docs/TRANSFER-ANCHOR.md
  and evidence/transfer-anchor-verification.md.

## Local send/receive experiment

- scripts/transfer_lab.py adds a separate local-only encrypted manifest and
  signed receipt experiment. Policy approver, sender and recipient are distinct
  Ed25519 roles. Fresh per-message AES-256-GCM keys/nonces bind payloads to context.
- The receiver checks policy, signatures, size and expiry before authentication/
  decryption, then commits a receipt under a unique local transfer ID. Restart,
  concurrent acceptance and local replay checks pass. The DB pins its policy.
- No chain anchor, RPC, read-ticket consumption, global release counter,
  protected key delivery, remote execution proof or quantum-safe authentication
  is supplied. Receipt/clock/DB trust boundaries have explicit tests.
- Public synthetic transcript: evidence/transfer-lab-demo.json. Dependency
  versions are pinned in requirements-lab.txt; full CI installs them and runs
  the demo. No keys, plaintext or private sessions are published.
- That checkpoint passed 170 checks (62 Rust + 108 Python), including 29 lab tests.
  Read docs/TRANSFER-LAB.md and evidence/transfer-lab-verification.md.

## Security target and paper alignment

- docs/SECURITY-TARGET.md now maps the source paper to current code, records the
  compromise matrix and describes the broader custody/data-access direction.
  Surviving authority, continued cold custody and rotation remain design gates.
- Three new native tests spend the actual normal/cold P2PK outputs to another
  destination, test wrong-role signatures, and link a complete recovery path
  through final P2PK spend. They make the end of covenant protection explicit.
- These use public fixture keys and VM verification, not quantum computation,
  a new live chain run or actual-age enforcement. Custody contracts, parameters
  and compiled artifacts are unchanged. No stronger security target is adopted.
- Historical live-proof limitations are now dated separately from later
  software. Remote cold signing remains future work; the recovery-only SSH kit
  exists and independent-host acceptance is still pending.
- That checkpoint passed 141 tests (62 Rust + 79 Python). See
  evidence/custody-boundary-verification.md for verification and limits.

## Bounded catch-up and developer experience

- Native scans include a sampled sink target. The watcher processes bounded
  local batches, checks recovery between commits, persists progress with its
  cursor and reports CHAIN_BACKLOG until the page and sampled target are caught
  up. Whole blocks are never split; removals stay atomic and budgeted.
- Restart preserves committed prefixes and signed outbox bytes. Audit stdout
  drains in bounded batches with a durable at-least-once delivery cursor.
- Upgrade native binaries and Python together. Bounds do not limit RPC bytes,
  memory or signing latency; deep reorgs/pruned history still require review.
- The README now includes the Kaspa custody vision, original SVG artwork,
  architecture, evidence, roadmap and a separate developer quick start.
- That checkpoint passed 138 offline tests (59 Rust + 79 Python). It was not a
  new funded run. See evidence/chain-batching-verification.md and
  docs/WATCHTOWER.md for behavior, upgrade requirements and limitations.

## Quarantine custody tracking update

- The protected watcher now retains exact quarantine outputs through accepted
  cold release and restores them after chain reorganization. Original recovery
  confirmation/outbox status survives the later cold exit.
- Health reports branch-current custody counts and incomplete legacy tracking.
  Legacy DBs or rollback snapshots with untracked quarantine require explicit
  reconciliation; no automatic historical reconstruction is attempted.
- The pilot requires the exact cold-exit observation before its success gate.
  This change does not modify contracts or submit funded transactions. Read
  docs/WATCHTOWER.md and evidence/quarantine-verification.md before upgrading.

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
- The current suite contains 221 offline checks (68 Rust and 153 Python). Read docs/ICP-Protected-Recovery-Live-Proof.md and
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

- The original implementation uses MIT; upstream licenses and the supplied
  papers retain their own terms. See NOTICE.md and docs/IMPORT.md.
- GitHub Actions reproduces the offline verification suite.
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

1. Resolve the security-target design gates: surviving authority, normal/cold
   protection boundaries, rotation and CANCEL timing semantics. Write the chosen
   next-generation transition/authorization table before changing contracts.
2. Install and validate the reviewed signer/supervision kit on independent hosts,
   verify host/descriptor pins and permissions, wire an approved external alert
   destination, and journal fresh TN10 acceptance. No hosts are configured yet.
3. Specify cold-stage rescue, key rotation and lost-key procedures before
   expanding custody claims; the final cold P2PK exit is not ongoing protection.
4. Complete external alert acceptance, database retention,
   deep-reorg/pruning reconciliation and RPC/resource limits beyond local batching.
5. Add fee estimation within the immutable cap, broader node/network failure
   testing, and independent adversarial review.
6. Keep data tickets, STARKs, DAG Zippers and STATIC separately specified.
   There is no mainnet-readiness or quantum-safety claim.
