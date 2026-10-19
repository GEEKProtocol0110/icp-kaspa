# Security target and paper alignment

This document distinguishes the implemented protected-v1 policy from the
broader ICP v2.0 paper and proposed next-generation requirements. It is a
traceability checkpoint, not an independent audit or an approved replacement
for the paper. Existing contracts and funded policies are unchanged.

## Intended scope

The long-term direction includes institutional custody and controlled access
to sensitive data, with Kaspa enforcing policy transitions and verifying
appropriate proofs. Banking and government environments are potential use
cases, not existing customers, certifications or demonstrated deployments.

| Layer | Intended responsibility | Current state |
| --- | --- | --- |
| Custody | Constrained withdrawals, monitoring and quarantine recovery | Experimental TN10 implementation and dated funded evidence |
| Private data | Encrypted off-chain storage, transport and recipient-specific key delivery | Local AES transfer and HPKE recipient-encryption experiments; remote storage/transport/release service unimplemented |
| Access policy | Read-intent tickets, persistent release accounting and proof/state binding | Local signed manifest checks and synthetic durable-ledger model; on-chain tickets, globally fenced accounting and proofs unimplemented |
| Operations | Independent signer/watcher hosts, external alerts and failure recovery | Offline-tested deployment kit; independent-host acceptance pending |

Sensitive records and decryption keys are not proposed as public ledger data.
Public commitments and access patterns still need metadata-leakage analysis.
External bank accounts and data services require authorized integration with
their own execution/access controls; the chain cannot impose rules on an
unrelated external system by itself.

Kaspa is the chosen platform. Block rate alone does not establish application
capacity or exclusive feasibility. Benchmark proof/transaction mass, fees,
verification work, tail latency, confirmation risk and private-service capacity.
The [Kaspa covenant model](https://docs.kaspa.org/programmability/covenants)
advances one shared state sequentially; independent states can run in parallel.
A global release counter may serialize access even when many vaults parallelize.
This project has not published a comparative benchmark establishing exclusive
feasibility on one chain.

The additive [transfer lab](TRANSFER-LAB.md) explores local before-send and
after-receive checks with conventional Ed25519 keys, AES-GCM and a trusted
policy/clock/replay database. It has no chain anchor or protected key delivery.
The companion [anchor observer](TRANSFER-ANCHOR.md) checks a pinned transaction
commitment against trusted-node accepted-chain scans with successor counting
and rollback. A [funded TN10 anchor](ICP-Transfer-Anchor-Live-Proof.md) has dated
observations from two endpoints. This supplies no consensus proof and does not
govern receiver acceptance or key release.
An acknowledgment is an authenticated recipient claim, not proof of execution
or factual truth. Local replay rejection does not provide global read limits.

The separate [recipient-encryption lab](RECIPIENT-ENCRYPTION-LAB.md) uses
library-provided HPKE base encryption, distinct X25519 delivery keys and
Ed25519 identity/approval signatures. A trusted local registry checks an encrypted
possession challenge and attests the pinned identity/key binding. No raw
symmetric key is handed to the recipient caller. This does not establish a
reviewed R0 delivery suite, secure hardware, real-world identity, network
delivery or chain-gated release. Later delivery-key compromise exposes earlier
messages; the design has no demonstrated post-quantum protection.

The [R0 read-ticket/release proposal](READ-TICKET-RELEASE-DRAFT.md) defines a
candidate service-enforced model, separate native ticket authority, stable
grant/budget accounting and irreversible disclosure history. A P2PK witness
does not enforce those access rules on chain. The proposal changes no current
security claim and explicitly leaves the all-secret/quantum target unresolved.

The [synthetic ledger model](RELEASE-LEDGER-MODEL.md) now exercises local
grant/quota persistence, authenticated retries and reorg/crash boundaries using
fake chain views and non-secret placeholders. It delivers no content key.
Copied databases and reorgs after the final sample have explicit counterexample
tests; neither global uniqueness nor atomic chain-to-delivery behavior is claimed.

The [native ticket design](NATIVE-TICKET-DESIGN.md) now proposes a concrete
TN10 issue/consume/refund profile. Refund is restricted to permanently closed,
never-reserved tickets and does not reset quota. Service rules choose one
terminal branch; P2PK consensus does not enforce that choice or service expiry.
The document separates native ID-bound semantics from mass/compute fields
excluded by the ID and signature hash, and from complete outbox integrity. It
adds no native ticket implementation, live acceptance, timed key recovery or
stronger claim.

The [native ticket lab](NATIVE-TICKET-LAB.md) now signs fabricated linked
issue/consume/refund layouts and tests them in the native VM. Tests demonstrate
ID/signature exclusions for compute budget and storage mass, full-hash integrity
checks, and arbitrary controller-signed P2PK spends outside ticket policy.
Both alternative terminal branches can be signed offline: the lab does not
enforce durable branch selection, actual authorization, consensus access limits
or chain acceptance. No real data key or release-model connection is added.

The separate [native fixture controller](NATIVE-TICKET-CONTROLLER.md) now
preserves a branch, charge and exact signed outboxes under the trusted recovery
model. It checks complete saved native records and never retries uncertain
synthetic effects. A real process crash and concurrent connections are tested.
Its independent authority remains a trusted local fake: joint restore can lose
history, direct worker use bypasses the controller, and no actual approval,
consensus observation or production signer enforcement is supplied.

The [release-service design](RELEASE-SERVICE-DESIGN.md) proposes a private key
vault, authoritative grant/response ledger and delivery gate, with independent
writer fencing and recovery checkpoints. It makes encrypted candidate responses
part of the disclosure boundary and defines revocation/dispatch ordering.
Those requirements are not implemented anti-rollback protection, hardware
isolation or a reviewed remote release service.

The [coordinator recovery model](RELEASE-COORDINATOR-MODEL.md) now exercises
separate synthetic vault/ledger/delivery stores with an independent fake
checkpoint authority. Trusted model boundaries reject stale generations and
restored component histories behind acknowledged checkpoints. This is not
production anti-rollback protection: all code/stores share a trusted host,
admission/authentication/administration are fixtures, and restoring the witness
with every store permits nonce reuse. No real keys or chain adapters are connected.
Revocation and reorg after dispatch acceptance still cannot recall bytes.

The [signed coordinator lab](SIGNED-COORDINATOR-LAB.md) adds conventional
two-role permissions, service-issued recipient challenges and signed grant
revocation to the recovery model. It binds actual admission/request digests
and atomically claims signed nonces with the relevant decision. Recipient
signing identity is pinned, but delivery-key binding and record/chain facts
remain fixtures. A copied signed request can be relayed once; restoring all
stores with the witness loses accepted revocation history. No encrypted key
response, remote transport, hardware isolation or R0 wire adoption is supplied.

The [bound response lab](BOUND-RESPONSE-LAB.md) now checks possession of a
pinned X25519 delivery key through a fresh HPKE-encrypted token, recipient
identity signature and approver authorization. A service certificate and exact
response record are saved under the recovery model's checkpoints. Client
verification binds intended permission/admission and exact dummy response.
This proves neither real-world identity nor exclusive/continued key ownership;
the service/expected-hash store remain trusted. HPKE encrypts enrollment only:
returned bundles are unencrypted placeholders and can be relayed with a copied
signed request. No content keys, native ticket, remote transport, independent
isolation or R0 wire adoption is supplied.

## Implemented protected-v1 claim

While value remains under the covenant, a compromised owner key cannot change
the pinned destination, bypass a fresh pending withdrawal's relative delay or
exceed the transition fee cap. A separate recovery trigger can move idle or
pending value into quarantine. After accepted recovery, owner and trigger keys
cannot release that value without the distinct cold key and a new, longer delay.

Timely recovery depends on correct consensus enforcement, trusted public policy
and approvals, usable node/signing services, adequate fees and inclusion before
a competing execution. Recovery has no guaranteed priority at maturity.
Native VM tests check signature/script and sequence commitments; the node
separately enforces actual UTXO age. DAA delay is not an elapsed-time guarantee.

This claim ends at **both normal and cold P2PK payouts**. Their new owners can
spend them to other destinations with ordinary P2PK authorization. The previous
covenant's destination, delay and fee restrictions do not follow those outputs.

## Compromise and failure matrix

| Compromise/failure | Current property | Remaining assumption or limitation |
| --- | --- | --- |
| Owner | Must follow permitted initiate/execute paths | Recovery availability and inclusion still matter |
| Recovery trigger | Can force quarantine but cannot perform cold release | Denial of service is possible |
| Owner + trigger | Cannot release accepted quarantine without cold authority | Normal execution can compete before quarantine is accepted |
| Cold authority | Release is pinned and delayed | No cold-stage rescue; final P2PK can be spent by that key |
| All role keys | All allowed signature-gated paths remain signable | No protection against eventual extraction through final payouts |
| Cold-key loss | No other role can substitute for cold release | Quarantined value is unavailable |
| Approval DB/watcher policy | On-chain layout/destination/fee bounds remain | Off-chain approval or response can be undermined |
| Node, network or signer outage | Durable state and outbox support restart | No guaranteed timely observation, signing or inclusion |

The cold public key is an immutable public contract parameter. Keeping its
private key offline does not make conventional Schnorr authorization resistant
to a hypothetical adversary capable of forging that signature scheme.

## Paper-to-code mapping

Source: the supplied four-page *Internal Command Protocol (ICP) - Technical
Whitepaper v2.0*, printed September 29, 2026. Page/section references below
identify that source without distributing or relicensing it. These differences
do not automatically represent bugs against the narrower implemented target.

| Paper requirement/claim | Code or evidence | Disposition |
| --- | --- | --- |
| Abstract and section 9: security despite compromised credentials | Conventional owner, trigger, recipient and cold keys | Stronger threat model unresolved; no all-key or quantum-safety claim |
| Section 3.1: protected cold recovery and rotation | Quarantine exists; keys remain immutable; final payout is P2PK | Rotation, cold rescue and continued custody need a new specification |
| Sections 3.1/8: one-block preemption and CANCEL minimum age | `recover` has no age guard; sequence is zero; funded response was 236 DAA units | Resolve minimum eligibility versus response target; neither establishes an inclusion SLA |
| Section 3.1: broadcast-time detection | Watcher acts on accepted virtual-chain changes | Deliberate observation choice; no mempool detection claim |
| Section 8: identical input/output script on every spend | State transitions preserve a template with changed state; payouts use explicit destinations | Replace literal equality with path-specific successor predicates |
| Section 8: EXECUTE locktime from creation DAA | Fresh pending output with relative CSV | Specify the intent anchor, DAA units and contextual maturity rule explicitly |
| Sections 5/8: read tickets and release velocity | Synthetic local ledger with permanent grant charges and fixed windows; no native tickets or real key release | Service fencing/recovery, wire/delivery and native ticket/refund rules remain gates |
| Sections 6/8: STARK-bound key release/DAG Zippers | No ICP circuit, proof-binding or key-delivery protocol | Missing integration, not blanket absence of upstream verification capability |
| Section 4: immediate irreversible defensive ordering | Trusted-node observations and explicit reorg rollback | No immediate-finality or mandatory-majority-attack claim |

The 18,000-block example in the paper is not a fixed test parameter. The
600/1,800-DAA normal/cold policy is a demonstration choice and does not establish
a production response window. The supplied paper does not define a recursive
cold state machine; recursion is an engineering option that still needs rules.

The pinned rusty-kaspa source includes `OpZkPrecompile` with `Groth16` and
`R0Succinct` tags; the RISC0 succinct receipt seal is a STARK. Our contracts
invoke neither. Selecting a hash-based proof component does not automatically
make conventional signature custody quantum-resistant or privately deliver a
decryption key. No verification-latency benchmark is claimed here. Exact
upstream revisions are recorded in [TOOLCHAIN.json](../TOOLCHAIN.json).

## Executable boundary evidence

Three tests in [protected_vm.rs](../tests/protected_vm.rs) make the payout
boundary inspectable using actual compiled covenant bytecode and native P2PK
script verification:

- `normal_payout_ends_destination_delay_and_fee_constraints`: the recipient
  signs a spend of the actual normal output to another destination, with zero
  sequence/locktime and a fee above the previous covenant cap; owner substitution
  fails at the P2PK stage.
- `cold_payout_ends_destination_delay_and_fee_constraints`: the cold key signs
  the equivalent follow-on spend; recovery-trigger substitution fails.
- `all_role_keys_allow_linked_recovery_and_final_p2pk_spend`: actual output IDs,
  scripts and amounts link initiation, recovery, cold release and a final P2PK
  spend. Possession of all fixture role keys permits that path.

Public deterministic keys simulate key possession. These tests do not compute
quantum signatures, mine blocks, prove actual age, induce a reorg or demonstrate
node acceptance of new transactions. The final spend exceeds the old fee cap
to demonstrate that the cap ends, not to recommend an operator fee.

## Decisions before a next-generation contract

These are proposed gates, not approved new custody rules:

1. **Surviving authority.** Specify separately an adversary that forges
   conventional signatures and one that possesses every accepted secret.
   Identify what still authorizes legitimate recovery. Safety and usable
   legitimate access must both be addressed; permanently freezing value is
   insufficient. No concrete new key scheme or threshold is selected here.
2. **Continued custody and exit.** Decide whether recovery must create another
   specified covenant and whether normal/cold terminal exits remain supported.
   Define exact successor scripts, permitted state changes, fresh clocks,
   cumulative fees and any rescue path. Recursion alone does not solve the
   surviving-authority problem.
3. **Rotation.** Specify the independent authority, source outpoint and successor
   policy commitment, version/replay binding, delay and any veto rule. A key
   assumed compromised cannot be the sole approval for replacing itself. State
   weakening, repeated clock resets, forced loops and fee exhaustion need rules.
4. **Time and evidence.** Resolve the CANCEL equation and define exact maturity
   boundaries, accepted-chain confirmation policy and rollback behavior. Define
   an operational response budget separately from a minimum script lock.

After those choices, write the complete transition table and adversary-oriented
acceptance cases before implementing new custody paths. Proposed data access
needs its own proof, accounting and private key-delivery specification. Once a
key/plaintext is disclosed, a later reorganization cannot erase that disclosure.
