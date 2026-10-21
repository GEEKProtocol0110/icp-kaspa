# ICP checkpoint - October 21, 2026

**Experimental Kaspa Testnet-10 prototype.** Vault withdrawals and protected
recovery have been tested with test coins. Real data-key delivery is still being
designed.

New here? Read [ICP in plain English](docs/PLAIN-ENGLISH.md) or browse the
[documentation directory](docs/README.md). This page records the current
engineering checkpoint first, followed by earlier milestones.

| At a glance | Current position |
| --- | --- |
| Vault and recovery | Dated testnet runs and automated verification |
| Data access | Local key-possession checks, signed requests/response records and synthetic recovery; no remote release service |
| Automated coverage | 694 tests: 126 Rust + 568 Python |
| Next engineering work | Bind P0 observations to private preparation, then separate live submission/reconciliation; verify key backup before funding |

## P0 observation checkpoint

- A separate [P0 observer](docs/TICKET-PILOT-OBSERVER.md) natively rechecks the
  operator public review and exact transaction projections, including compute
  budgets and storage mass. It checks positive funding-source/ticket UTXOs,
  complete metadata and fresh accepted-chain/depth observations from two hosts.
- Reorgs revoke observations; different entries, stale views, backlog, unknown
  spends or changed policy/binaries block the paired report. P0/LAB0 database
  reuse fails; the fixture controller cannot accept the new tracker type.
  A public `observe` CLI is read-only and closes both handles after polling.
- Three new Rust and 34 Python tests bring coverage to 694 (126 Rust + 568
  Python). Full local locked Rust/Python suites, compilers, formatting and public
  fixture checks pass; final-head CI is required before merge. See the
  [verification record](evidence/ticket-pilot-observer-verification.md).
- This milestone uses synthetic pages and makes no live P0 calls or broadcasts.
  A malformed-signature counterexample demonstrates reliance on node acceptance.
  Distinct hosts do not prove operator independence; reads are not atomic.
  Next bind the current pair to new private preparation under its journal lease,
  then implement separate live submission/reconciliation before a backed-up pilot.

## Private P0 preparation checkpoint

- The [private preparer](docs/TICKET-PILOT-PRIVATE.md) signs the same native P0
  layouts as the public reviewer using supplied role keys. It checks exact
  asserted entries, minimal Schnorr signatures, native script execution, full
  RPC semantics and complete hashes. Public fixture mode/keys remain rejected.
- A separate private journal saves signing intent before key access, permanently
  chooses one terminal branch and recovers exact signed outboxes. A shared
  trusted registry prevents another local journal claiming the same source.
  Unknown signing outcomes stop without automatic re-signing.
- Five new Rust and 28 Python tests bring inventory to 657 (123 Rust + 534
  Python). The changed examples' 13 cached native tests and all Python checks
  run locally; the unavailable pinned source checkout prevents a full local
  Cargo run. Locked clean-source CI is required before merge. See the
  [verification record](evidence/ticket-pilot-private-verification.md).
- This is offline, with fabricated test inputs and ephemeral keys. No operational
  keys, funding request, live calls or broadcasts were created. Local branch
  policy is bypassable with the key, and joint trusted-store rollback is an
  explicit counterexample. Next: profile-aware P0 observation and separate live
  submission/reconciliation gates before a backed-up fresh-key pilot.

## Unsigned pilot preparation checkpoint

- [P0 review](docs/TICKET-PILOT-PREPARATION.md) accepts public native role keys,
  an exact asserted source and a non-secret evidence commitment. Native APIs
  calculate unsigned issue/consume/refund layouts and IDs; terminal previews
  spend the exact issue ID/index 0. No signer/RPC/effect command is exposed.
- Operator and public-fixture modes are separate; fixture relabeling, shared
  roles, unknown/private fields and ambiguous numeric encodings fail. A public
  checksum receipt is exclusively saved and natively recomputed on verification.
  It is not an approval, source claim, signed outbox or submission journal.
- Eight new Rust and 18 Python tests bring inventory to 624 (118 Rust + 506
  Python). All 506 Python tests and eight cached native review tests passed
  locally. Local Cargo dependency checkout was unavailable; full locked native
  verification is required through CI. See the
  [verification record](evidence/ticket-pilot-review-verification.md).
- The [pilot sequence](docs/TICKET-PILOT-PREPARATION.md) defines separate consume
  and unused-refund runs, source/value checks, fee bounds and recovery gates.
  No operational keys, funding request, signature, broadcast or live call was
  made. P0 is separate from LAB0/N0/R0 and is not wired into fixture controllers.
  Next: private fresh-key preparation/journal and explicit P0 observation support.

## Observer/controller integration checkpoint

- The [connected fixture controller](docs/NATIVE-TICKET-BINDING.md) pins two
  separate observer stores and exact native semantics in its policy. New work
  rechecks current observations under the controller lease; copied dictionaries
  and legacy fake acceptance maps cannot satisfy this variant.
- Native unsigned pins identify alternative outcomes without signing them.
  Complete saved signed records still receive the separate native integrity/VM
  checks. Reorgs and observation-store restore cannot rewind permanent branch,
  charge, outbox or submission history.
- 34 new Python and two native tests bring full local verification to 598
  (110 Rust + 488 Python). Tests cover restart, depth, freshness, exact context,
  lost replies, a reorg between intent and final lease and an explicit change
  after the last sample that still allows the local fake effect.
- The experiment uses fabricated native inputs and synthetic full RPC bodies.
  No live calls, funded ticket, real authorization or content key is connected.
  Direct known-key worker use and joint service-authority rollback remain limits.
  Read the [verification record](evidence/native-ticket-binding-verification.md).
  Next: prepare a fresh-key TN10 pilot plan and review the independent boundaries.

## Read-only native ticket observer checkpoint

- [Observer](docs/NATIVE-TICKET-OBSERVER.md) uses a dedicated read-only native
  binary to recompute RPC transaction IDs and project exact issue/consume/refund
  semantics. It checks exact ticket UTXOs and reverses accepted-chain events.
- Separate per-endpoint databases, fresh scans after restart, bounded local
  reply checks, successor depth and positive branch-linked UTXO samples block
  stale or incomplete status. Paired observations must match and come from
  distinct hostnames; different names do not establish operator independence.
- 38 new Python and eight Rust tests bring local verification to 562
  (108 Rust + 454 Python). Reorgs reset observations without changing the
  controller's branch, charge or outbox. Read the
  [verification record](evidence/native-ticket-observer-verification.md).
- The public demo uses fabricated full RPC bodies with native fixture IDs.
  The demo makes zero RPC calls, signatures or broadcasts; tests use known-key
  native fixtures. This milestone made no live RPC calls. No actual native
  ticket, controller integration, permission or data-key delivery is claimed.
  Next: test an explicit observer/controller boundary with synthetic inputs.

## Persistent native fixture controller checkpoint

- [Controller](docs/NATIVE-TICKET-CONTROLLER.md) saves exact native issue and
  selected terminal outboxes under the existing hash-chained journal and separate
  trusted checkpoint/fencing authority. Branch choice commits before signing.
- Recovery verifies exact native records without re-signing. Uncertain synthetic
  submissions reconcile only; branch, charge and original deadlines remain.
  Status exposes metadata/hashes, not signed transaction bytes.
- 37 new Python and four new Rust tests bring full local verification to 516
  (100 Rust + 416 Python), including actual process exits and concurrent stores.
  Shared-authority component rollback halts; joint authority rollback remains
  an explicit counterexample. Read the
  [verification record](evidence/native-ticket-controller-verification.md).
- No actual authorization, native observation, funded transaction, real key or
  remote release is added. Direct known-key worker use bypasses the controller;
  independent deployment enforcement remains a gate. Next: read-only native
  ticket observation, separate from all private signing/effect paths.

## Offline native ticket checkpoint

- [Native ticket lab](docs/NATIVE-TICKET-LAB.md) builds and signs issue,
  consume and refund fixtures with native Kaspa transaction/hash/script APIs.
  Terminal inputs link to the actual calculated issue ID and output index.
- Closed canonical lab plans pin a fabricated source, known distinct keys,
  exact amounts/outputs, purpose-bound commitments, mass and compute budget.
  Full native saved-hash checks complement layout/VM and transaction-ID checks.
- 28 new native tests cover mutations, field encoding and scope boundaries.
  The complete local suite passes: 475 tests (96 Rust + 379 Python). Public
  fixture vectors reproduce; standard-library Python independently verifies
  their commitment digests. The runnable example is also checked by CI.
- Tests deliberately show arbitrary controller-authorized P2PK spends and both
  conflicting terminal fixtures. No durable branch controller, actual permission
  or refund-history check, RPC, broadcast, real-key/model integration or live
  acceptance is implemented. It uses a separate lab domain rather than N0 wire.
- Read [the verification record](evidence/native-ticket-lab-verification.md).
  Next: fixture-only durable branch selection/outbox recovery and crash tests.

## Native ticket design checkpoint

- [docs/NATIVE-TICKET-DESIGN.md](docs/NATIVE-TICKET-DESIGN.md) proposes N0:
  one funding input creates a dedicated P2PK ticket plus change; consume or
  refund spends the exact ticket to one pinned return destination at fixed fees.
- Commitment ordering avoids future-ID self-reference. Pinned native source
  review distinguishes transaction IDs and signature commitments from complete
  saved signatures, storage mass and V1 compute budgets.
- The authoritative ledger permanently chooses consumption at reservation or
  refund at unused expiry/revocation closure, before signing. Refund is forbidden
  after reservation, consumption planning or response history. It resets no quota.
- Unknown effects reconcile read-only. Reorgs preserve branch, claims, closure,
  charges and disclosure history. P2PK key loss has no independent rescue, and
  copied signed transactions cannot be recalled by fencing or service expiry.
- Documentation-only milestone: existing 447-test implementation is unchanged.
  No native ticket code, broadcast, funded run or real-key connection is added.
  See [evidence/native-ticket-design-review.md](evidence/native-ticket-design-review.md)
  for review scope and validation. This is not independent security review.
- Next: offline native preparer, strict closed schemas/vectors and mutation tests
  with public fixture keys; no RPC, broadcast or release-model connection.

## Delivery-key binding and signed response checkpoint

- scripts/bound_response_lab.py extends the signed recovery flow with a distinct
  lab protocol for X25519 enrollment and response attestations. Policy commits
  the exact delivery public key/epoch, recipient identity, service/budget and
  suite. A fresh HPKE-encrypted random token requires the delivery private key;
  separate recipient and approver signatures precede service certification.
- Enrollment nonces/certificates share one checkpointed ledger event. Response
  records share their private candidate's vault event and copy exactly into
  the ledger response commit. Retries/restarts return identical complete bundles,
  retain one charge, and halt on mismatched/lost records without re-signing.
- A public client verifier checks the intended permission/admission, registration,
  exact dummy response and service signature. Status/binding reads expose no
  pending response or signature. All public demo objects are explicitly synthetic.
- 45 new tests bring the suite to 447 (68 Rust + 379 Python), including an actual
  child-process exit after vault commit and before checkpoint acknowledgment.
  Python passes locally; required native/build/template checks run in CI.
- HPKE encrypts only the enrollment token. Returned bundles are unencrypted
  placeholders, with a test showing relay of a captured signed request. There
  are no content keys, real record validation, native tickets, RPC, remote
  endpoint, protected hardware or adopted R0 wire/suite.
- Independent authority history, local administration and clocks remain trusted.
  Existing rollback and final-check-to-arrival limits remain; an old signature
  staying verifiable after revocation is not permission for another delivery.
- Read docs/BOUND-RESPONSE-LAB.md and evidence/bound-response-verification.md.
  Next: review these formats and specify native ticket/consume/refund bindings
  before connecting real content keys. Protected storage/delivery, independent
  enforcement and authenticated transport remain separate acceptance gates.

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
