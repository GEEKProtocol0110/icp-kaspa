# ICP continuation checkpoint

Current milestone: [encrypted PQ software keys](PQ-ENCRYPTED-KEYSTORE.md).
`pq_locked_adapter.py` uses Argon2id/AES-256-GCM to protect fresh endpoint
seeds before writing files. Hidden/FD unlock preserves the PQ wire profile;
there is no password argument, environment lookup or plaintext-key migration.
Encrypted key backup verification pins an independently authenticated public
fingerprint. Backups contain keys only; no endpoint-state restore is supplied.
Retain policy DBs and `.icp-state-guard` markers. Missing/incomplete initialized
state blocks use. A crash during initial setup can leave a blocking marker;
do not erase it to retry. Whole-store rollback/copying still defeats local
history; no hardware or global anti-rollback claim exists.
Initial CI attempts stalled in the concurrent-unlock case. Argon2id calls are now
serialized per process, and that acceptance test uses a separate exec process
with a 20-second hard timeout and diagnostic stacks. CI fails fast on a Python
failure; a successful run must still execute all 828 Python tests. Check the
current head rather than treating a timed-out attempt as validation.
Forty new tests plus all 121 earlier recipient tests pass locally; the
17-process encrypted-key demo passes. Inventory: 970 tests (142 Rust + 828
Python). Native/full checks require CI because cargo is unavailable locally.
Next work: authenticated remote transport/identity, reviewed hardware-backed
key integration, rotation/recovery and independent protocol review. Existing
funded sessions and pinned workers were not opened or changed.

Earlier milestone checkpoints follow.

Current milestone: [experimental PQ recipient profile](POST-QUANTUM-RECIPIENT-PROFILE.md).
The separate `pq_recipient_lab.py` and `pq_recipient_adapter.py` use library
ML-KEM-768/X25519 HPKE and ML-DSA-65 signatures with SHA-384 commitments.
Its distinct keys/namespace/fixed suite/96-character policy pin reject classical
fallback and implicit migration. Fifty new tests and the separate-process
fictional PQ binary exchange pass locally; all 71 conventional recipient tests
also pass. Inventory is 930 tests (142 Rust + 788 Python). Rust and native
workers are unavailable locally; complete CI remains required before merge.
This does not upgrade Kaspa's native signatures, vaults or R0 release suite.
No overall quantum-safety, FIPS certification or audit completion is claimed.
Maintain owner-only TEST keys/state, policy authentication, 64 KiB payload cap
and receipt-before-export behavior. Static-key compromise exposes history;
copied stores can accept again. Next: reviewed device keystores/recovery,
authenticated transport/identity, rotation and independent protocol review.
No saved funded journal, pinned worker, source claim or private outbox changed.

Earlier milestone checkpoints follow.

Current milestone: [recipient file/bytes adapter](RECIPIENT-FILE-ADAPTER.md).
The recipient HPKE lab now has a Python API and file CLI with separate sender,
approver and recipient test-key endpoints. The separate-process fictional binary
demo passes locally through a ciphertext-only loopback HTTP relay, with 34 new
Python tests. Inventory is 880 tests (142 Rust and 738 Python); full native/build
verification must pass CI before merge.
This is a one-host exchange, not remote delivery, independent-device
isolation, reviewed R0 key release or quantum protection. Maintain the existing
64 KiB limit, authenticated policy pin, owner-only test keys and replay DB.
File export is not atomic with receipt acceptance; recover saved receipts on
failure without deleting/reinitializing state. The next data integration needs
authenticated transport and reviewed device keystore/recovery boundaries.
No saved P0 worker, policy, private journal, source claim or outbox was changed.
The historical catch-up/funded continuation below retains its recorded approval
and reconciliation requirements; do not infer that a new funded run occurred.

Earlier milestone checkpoints follow.

Current milestone: [bounded historical catch-up](TICKET-HISTORY-CATCHUP.md).
The user explicitly approved four TN10 transactions with an 8,000,000-sompi fee
ceiling, but refreshed reads hit an oversized history frame. Operators stopped
with the two saved issuances intact and zero submission intents. A separate
helper advances full historical pages through the existing observer validator,
then invalidates readiness. Copied-store live probes advance without eligibility.

Run catch-up only with old live operators closed, and retain the original
observer configurations/bootstrap, binary pins, source claims, authorities and
private journals. Pin the auxiliary helper separately in the trusted operator
gate. Never rebuild old pinned workers, relabel a database or replace historical
acceptance lists with partial transaction bodies. Catch-up is not a UTXO sample
and cannot authorize a send. Reopen/reconcile the original live controller with
fresh original pinned snapshots before any effect. Explicit approval is already
recorded privately; do not ask again for the same four-transaction scope.
Inventory is 846 tests (142 Rust + 704 Python).

Earlier milestone checkpoints follow.

Current milestone: [funded P0 preparation](TICKET-PILOT-FUNDED.md). Two issuance
outboxes are signed and natively verified, with two permanent source claims.
Both signing intents were checkpointed before key access and the final private
checkpoint retains both outboxes. Both operators are stopped pending explicit
submission approval. All submission intents/replies are absent; no terminal
branch was chosen or signed. A subsequent read from both nodes still reported
the full 48,000,000 sompi unspent.

Resume the existing journals and exact signed records after approval and code
gate review; do not reinitialize claims or re-sign either issuance. Refresh the
pinned observers before any effect. A stale cursor or bootstrap-crossing reorg
may block recovery; never silently reset it. Any future submission intent, even
a rejected or unknown one, permits read-only reconciliation only. The planned
fee ceiling is 8,000,000 sompi for four TN10 transactions across two lifecycles.
No ticket acceptance, actual authorization or data-key delivery is established.
Inventory remains 835 tests; local suites and both exact-head CI runs passed
for the merged reader repair.

Earlier milestone checkpoints follow.

Current milestone: [P0 live read-path repair](TICKET-PILOT-READ-PATH.md). Both
funding sources arrived and were verified at 24,000,000 sompi each. Three earlier
preflight profiles were retained/halted with zero claims, signing intents,
outboxes and submissions. The new native snapshot reads both roles and history
on one bounded connection while preserving the existing eligibility checks.
The live two-node source probe passed; it did not sign or submit anything.

Inventory is 835 tests (140 Rust + 695 Python). Native request/row routing,
snapshot identities, request-start age, partial history, branch brackets and
relay failure/cleanup have regression coverage. The new read profile and binary
hashes change policy identities; never relabel old journals or rebuild their
pinned workers while active. Both old and new forensic build records must stay
private, alongside the separately verified test-key archive.

At the read-path milestone, the next step was a new reviewed profile to run the
funded consume and unused-refund pilots separately. Keep ten successors and the
preselected thirty-second binding policy; do not silently widen a running one.
Preserve exact outboxes and durable attempts; reconcile any attempted/unknown
send without retry. Bounded history/frame limits can still halt the reader.
[Live read-only evidence](../evidence/ticket-pilot-read-path-live.json).

Earlier milestone checkpoints follow.

Current milestone: [P0 test-key setup](TICKET-PILOT-KEYS.md). Two new consume and
refund sessions have six distinct test-only keys. Exact backup restoration,
domain-separated possession proofs and fresh restored-key challenges passed.
The private archive was saved durably before public funding details; no keys,
private journals or outboxes are in Git. The
[public setup receipt](../evidence/ticket-pilot-key-preparation.json) pins the
session and backup digest, with zero transaction signatures/RPC calls/broadcasts.

Inventory is 813 tests (136 Rust + 677 Python). The reviewer's new public-only
`addresses` command changes its binary hash; new plans/observers must pin the
current build. Restore files to new private paths, verify the trusted archive
digest, and do not treat a key backup as current live-state recovery.

Next obtain one 24,000,000-sompi output per session on TN10, inspect exact
source entries through both configured nodes, then separately exercise consume
and unused refund with durable journals and read-only reconciliation. No live
P0 handshake, funded acceptance, actual authorization or data delivery is
demonstrated. [Verification/funding](../evidence/ticket-pilot-keys-verification.md).

Earlier milestone checkpoints follow.

Current milestone: [P0 native submission adapter](TICKET-PILOT-LIVE.md). A
distinct live policy connects durable attempts to the TN10 sender. Its endpoint
must match the first observer. Native verification, connected-node gates, exact
positive input metadata and original observation deadlines apply before one
submit API call. Bounded transport I/O and process-group termination preserve
uncertain outcomes for read-only reconciliation; replies are not confirmation.

Inventory is 799 tests (134 Rust + 665 Python), including eight native and 27
Python additions. Build `ticket_pilot_submit` alongside all earlier workers
before Python tests. The private record verifier moved into shared support;
wire semantics are unchanged but compiled build hashes change. Never rebuild
pinned workers while journals/tests are using them or silently migrate policies.

New evidence is offline/simulated; no successful P0 RPC handshake/submission or
funded lifecycle was performed. Next verify fresh operational role-key backup
and possession, then separate funded consume/refund pilots. No keys or funding
request were generated here. [Verification](../evidence/ticket-pilot-live-verification.md).

Current milestone: [P0 submission journal](TICKET-PILOT-SUBMISSION.md). The
distinct controller journals one intent before a simulated send and refuses
every repeat submission call. It rechecks native outboxes, fresh paired input
metadata and writer generation before the effect. Separate private preparation
and submission components share the independently stored checkpoint authority;
the permanent source registry remains shared across variants.

Coverage is 764 tests (126 Rust + 638 Python), with 38 new submission tests.
Actual process deaths, unknown replies, restored components, stale writers and
revocable reconciliation are exercised with simulated node/transport evidence
and temporary unfunded keys. No live P0 transaction was submitted. A post-sample
reorg can precede the effect; jointly restoring all trusted stores can repeat it.
Next: a separately pinned, bounded TN10 native transport without automatic retry,
then operational role-key backup/possession checks and independent funded pilots.
[Verification](../evidence/ticket-pilot-submission-verification.md).

Current milestone: [P0 observation/private binding](TICKET-PILOT-BINDING.md).
The new pair/controller variant pins two exact P0 trackers and requires current
unspent source/ticket observations and matching entry metadata before new
signing or branch choice. It rechecks age after slow verification/status/key
reads. Recovery preserves outboxes/choices and invalidates observer eligibility.
Offline and bound journals have distinct policy identities; they cannot be
silently interchanged. The shared source registry retains permanent claims.

Coverage is 726 tests (126 Rust + 600 Python), including 32 new binding tests.
New evidence is synthetic with temporary unfunded role keys; no P0 submission
or funding was performed. A post-sample counterexample still permits signing
after a view change. Direct worker/key use and joint trusted-store rollback
remain limits. Next add separate durable live submission intent/reconciliation,
then verify operational key backup/possession before the two funded pilots.
[Verification](../evidence/ticket-pilot-binding-verification.md).


Current milestone: [P0 observation](TICKET-PILOT-OBSERVER.md). The separate tracker
pins a natively reverified operator review, full P0 semantic/compute/storage
projections and exact positive source/ticket entries. Two distinct node views
must agree under the same freshness/depth policy; reorgs revoke observations.
The `observe` CLI has no signing/submission path. LAB0 behavior remains separate.

Coverage is 694 tests (126 Rust + 568 Python); full locked Rust and Python suites
run locally. New P0 evidence is synthetic; no live P0 call or funded lifecycle
was made. Node acceptance, local storage/clock and node-operator independence
remain trust assumptions. Next bind this pair to new private preparation under
the journal lease, then add durable live submission/reconciliation. Back up and
verify operational role keys before funding. [Verification](../evidence/ticket-pilot-observer-verification.md).


Current milestone: [private P0 preparation](TICKET-PILOT-PRIVATE.md). Native
signing uses supplied role keys and the shared unsigned builder. Its separate
private journal reserves before key access, claims exact sources through a
shared trusted registry and preserves branch/outbox history across recovery.
There is no RPC or submission path. Unknown signing outcomes stop without
re-signing; joint trusted-store rollback remains an explicit counterexample.

Inventory: 657 tests (123 Rust + 534 Python). Build ticket_pilot_private alongside
the other native workers before Python tests. New tests use temporary ephemeral
keys and fabricated entries; no operational wallet or P0 live run exists.
Next implement explicit P0 observation and dual-node source/acceptance checks,
then a separate live submission journal. Verify operational key backup/restore
before requesting funding. [Verification](../evidence/ticket-pilot-private-verification.md).


**October 20, 2026 UTC: unsigned P0 pilot-review preparation implemented.**

For a nontechnical introduction, open [ICP in plain English](PLAIN-ENGLISH.md).
The [documentation directory](README.md) separates explanations, dated testnet
evidence, operating guides and research proposals. This handoff preserves the
engineering and operational detail needed to continue development.

## Current state

The latest milestone is [TICKET-PILOT-PREPARATION.md](TICKET-PILOT-PREPARATION.md).
examples/ticket_pilot_review.rs builds unsigned P0 previews for public role keys
and an asserted exact source. scripts/ticket_pilot_review.py saves/verifies public
checksum receipts; it has no signing, RPC or submission command. P0 commitments
and modes are distinct from LAB0 and proposed N0/R0. Never fund public fixtures.

Inventory is 624 tests (118 Rust + 506 Python), with eight new native and 18
Python tests. Local Python regression and cached native review tests pass; a
fresh local Cargo checkout was blocked, so full locked native verification must
pass in GitHub CI. The workflow and quickstart build ticket_pilot_review before
Python tests and run its no-argument public-fixture demo. Read
[the verification record](../evidence/ticket-pilot-review-verification.md).

No operational keys or funding address/request were generated. Next implement
and test the separate private P0 preparer/live journal and profile-aware
observations. Back up and verify fresh test keys before any funding request;
retain exact outboxes and source claims on unknown results. The guide defines
two independent future runs for consumption and unused refund. No real key
delivery or actual permission integration is supplied.

The preceding milestone is [NATIVE-TICKET-BINDING.md](NATIVE-TICKET-BINDING.md).
scripts/native_ticket_binding.py binds exact native tracker pairs to a separate
controller policy. It rechecks unspent observations before new work, rejects
legacy fake-map reconciliation, requires fresh scans/reconciliation after
recovery, and preserves branch/charge/outbox/attempt history across reorgs.
Unsigned native worker pins describe potential outcomes without signing either
terminal branch. Build native_ticket_worker and ticket_read before Python tests.

Full local verification is 598 tests (110 Rust + 488 Python), with 34 new Python
and two Rust tests. CI runs the offline integration demo. No live RPC, funded
ticket or real key is connected. A change after the final sample can still
precede a fake effect; direct fixture-worker use and joint authority rollback
remain explicit limits. Next prepare a fresh-key TN10 pilot plan and review
signing, wire, authorization and protected-key boundaries. Read
[the verification record](../evidence/native-ticket-binding-verification.md).

The preceding milestone is [NATIVE-TICKET-OBSERVER.md](NATIVE-TICKET-OBSERVER.md).
scripts/native_ticket_observer.py maintains separate reversible per-node history;
examples/ticket_read.rs only projects native transactions or reads scans/UTXOs.
Build both ticket_read and native_ticket_worker before the Python suite; CI and
the quickstart include them. New native projection tests reject copied IDs over
changed bodies. Scan tests cover depth, exact live-UTXO shape, reorgs, restart,
clock continuity, partial pages, unknown spends and two-node disagreement.

Full local verification is 562 tests (108 Rust + 454 Python). The demo and
38 new Python tests use synthetic chain records; this milestone makes no RPC
calls or broadcasts. The demo creates no signatures; tests may prepare public
known-key native fixtures. Observation is not a
permission, consensus proof or new release decision. The controller remains
separate with FakeNode acceptance. Next: explicitly integrate observer facts
with that fixture controller, preserving irreversible branch/charge/outbox
history across reversible scans. Read
[the verification record](../evidence/native-ticket-observer-verification.md).

The preceding milestone is [NATIVE-TICKET-CONTROLLER.md](NATIVE-TICKET-CONTROLLER.md):
scripts/native_ticket_controller.py uses the existing journal/authority model
to persist branch choice before signing and recover exact private native
outboxes. examples/native_ticket_worker.rs validates/prepares/verifies bounded
fixture records through a private channel; recovery verification does not sign.
Build that example before running the Python suite. CI now does so explicitly.

37 Python plus four Rust tests bring local verification to 516 (100 Rust +
416 Python), including actual child-process exits, concurrent branch choices,
unknown effects and restore. The authority must not roll back with the component;
joint rollback loses branch history in a counterexample. Direct fixture worker
use bypasses the controller, so this is not independently enforced signing.
No RPC, real authorization, funded state or data key is connected. Next build
dedicated read-only native ticket observation; keep signing and effects separate.
Read [the verification record](../evidence/native-ticket-controller-verification.md).

The preceding native layout milestone is [NATIVE-TICKET-LAB.md](NATIVE-TICKET-LAB.md),
implemented in src/native_ticket_lab.rs and examples/native_ticket_lab.rs.
It builds linked native issue/consume/refund fixtures with known public keys,
strict canonical plans, exact layout/mass checks, native Schnorr/VM verification
and complete saved-hash comparison. Public vectors include every plan and
commitment; no signed outbox or private material is published.

Twenty-eight new Rust tests bring local verification to 475 (96 Rust + 379
Python). They also prove the scope limits: ordinary P2PK admits arbitrary
controller-signed spends, and both alternative terminal branches can be signed.
Evidence/approval/closure digests are invented, not verified permissions.
No RPC, persistent controller, live observation or real-key connection exists.
Its lab namespace/prefix does not adopt the proposed N0/R0 wire protocol.

Next: separate fixture-only durable controller with one permanent branch,
exact saved transaction recovery and crash/unknown-effect tests. Keep funded
sessions, real keys, chain adapters and release models disconnected. Read
[the verification record](../evidence/native-ticket-lab-verification.md).

The governing design is [NATIVE-TICKET-DESIGN.md](NATIVE-TICKET-DESIGN.md), with
review scope in [its checkpoint record](../evidence/native-ticket-design-review.md).
It selects the proposed N0 issue/two-output and terminal/one-output layouts,
fixed experimental fees, noncircular commitments, irreversible branch selection
and never-reserved-only refunds. Refund recovers coins, never permissions/quota.
Native IDs do not identify every saved field; pin complete outboxes separately.
Service fencing/expiry cannot retract copied signed spends. The later lab
above tests native layouts; complete N0 schemas/authorization, independent
signer continuity and accepted-chain integration remain gates.

The earlier bound response module is scripts/bound_response_lab.py. Read
[BOUND-RESPONSE-LAB.md](BOUND-RESPONSE-LAB.md) and
[its verification record](../evidence/bound-response-verification.md).
The signed policy's binding label now commits to a pinned X25519 delivery key,
identity, service/budget, epoch and suite. HPKE encrypts a fresh registration token;
recipient/approver signatures and private expected-hash comparison precede a
service certificate saved with the used nonce in one ledger event.

A response record shares the candidate's private vault event, copies exactly
to the response commit and returns in a canonical bundle only through fresh
signed retrieval. Public client verification binds the intended permission and
original admission. Forty-five new tests bring the suite to 447 (68 Rust + 379
Python), including actual process exit after vault save before acknowledgment.

Only the enrollment token is encrypted: response bundles remain non-secret,
unencrypted fixtures, with a relay counterexample. There is no content key,
real record validation, RPC, native ticket/refund, transport or protected host
boundary. Independent authority history/clock/admin trust and final-sample races
remain. Earlier lab encodings are not R0 adoption. The native design above
now specifies an initial proposal; review and offline implementation precede
real-key integration. Protected storage/delivery and independent enforcement
remain separate gates.

The earlier signed module is scripts/signed_coordinator_lab.py. Read
[SIGNED-COORDINATOR-LAB.md](SIGNED-COORDINATOR-LAB.md) and
[its verification record](../evidence/signed-coordinator-verification.md).
Separate approver/sender, recipient, service-challenge and revoker Ed25519
roles bind complete permissions and fresh purpose-bound requests. Shared base
transaction helpers commit signed evidence and used nonces atomically with
reservation/delivery; the response context binds permission and admission digests.
At that checkpoint, forty-eight new tests brought the suite to 402 (68 Rust + 334 Python), including
an actual subprocess crash in the signed reservation commit/acknowledgment gap.

This has a distinct experimental lab encoding, not an adopted R0 wire format.
Delivery-key binding, record/chain facts and administration remain fixtures;
responses stay non-secret. The earlier HPKE lab is not connected. A copied
signed retrieval can be relayed once, and joint authority/store rollback loses
signed revocations. Keep the independent authority outside component restores.
The bound response layer above now adds separate cryptographic enrollment and
response records. Real key custody/delivery, protected enforcement, transport
and native ticket/refund remain separate gates.

The earlier recovery module is scripts/release_coordinator_model.py. Read
[RELEASE-COORDINATOR-MODEL.md](RELEASE-COORDINATOR-MODEL.md) and
[its verification record](../evidence/release-coordinator-verification.md).
Separate ledger/vault/delivery SQLite journals pin an independent authority
identity. Active writer generations, exact acknowledgments and cross-store
response checks gate recovery and dispatch. At that checkpoint, fifty-two new
tests brought the suite to 354 (68 Rust + 286 Python), including real process termination and restore
counterexamples. Keep the authority outside component backup/restore operations.

That base experiment retains its unsigned harness API; the signed layer above
adds separate entry points. Record/ticket/chain facts and administration remain
fixtures in both. Restoring the witness with all stores loses history, and
accepted dispatch cannot recall bytes. No production fencing provider, protected
vault, remote endpoint or R0 wire/suite is selected. Real key storage/delivery,
independent enforcement and native ticket/refund need separate gates.
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
