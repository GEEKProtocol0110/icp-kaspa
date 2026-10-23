# ICP core integration and continued-custody draft

[Documentation](README.md) · [Security target](SECURITY-TARGET.md) · [Current v1](PROTECTED-RECOVERY.md)

Status: **design candidate C0, not an implemented custody profile or a KIP**.
Prepared October 23, 2026. Existing v0/v1 contracts, deposits, signers, watcher
rules and private P0 journals are unchanged. This document authorizes no signing,
funding, network submission or migration. Research targets Testnet-10 only.

## Decision and immediate deliverable

Investigate continued recovery custody and role-key replacement using existing
Kaspa scripting first. No missing consensus primitive has yet been demonstrated.
Do not add an ICP opcode or fork the node merely to give the project a core label.

The next executable deliverable is a separate offline C0 state-transition model
with adversarial counterexamples. Native compiled-contract tests come after the
authority, encoding, fee and successor-template gates below are resolved. A
model that accepts a transition is not evidence that Kaspa can enforce it.

The intended improvement is specific: accepted recovery should retain protected
custody, and a reviewed independent authority should be able to replace affected
role keys without a compulsory payout to an ordinary address.

## Current evidence and boundaries

The [v1 policy](PROTECTED-RECOVERY.md) has idle, pending and quarantine states.
Owner initiation creates a fresh pending UTXO. Execution waits for its relative
delay and exits to a fixed normal P2PK recipient. Recovery moves idle or pending
value into quarantine; a separate cold key can later exit to a fixed cold P2PK
destination. Both exits end the covenant's later-spend protection.

Current public evidence records TN10 acceptance and early-payout rejection for
v1. It does not establish the C0 proposal, key rotation, independent-host
operation, post-quantum custody or guaranteed recovery inclusion. See the
[live record](ICP-Protected-Recovery-Live-Proof.md) and
[compromise matrix](SECURITY-TARGET.md#compromise-and-failure-matrix).

## Candidate surviving authority

C0 assumes an independent guardian quorum remains secure when operational role
keys are stolen. The candidate is two distinct signers from three immutable
guardian public keys. This is a proposed conventional-signature authorization
profile for review, not a selected production governance policy.

Roles:

- `O`: operational spending authority.
- `R`: recovery trigger; can quarantine but cannot choose a payout.
- `C`: cold co-approver for routine replacement.
- `P`: fixed normal payout recipient for the current policy generation.
- `G`: two-of-three guardian quorum, separate from all four role keys.

The four role public keys must be distinct. Guardian keys must be pairwise
distinct and disjoint from role keys, including replacement keys. Fresh keys
require separate possession checks; signatures never prove human intent or
independent host custody. Each signer must check the exact reviewed transition
and successor policy through an authenticated independent path.

`G` can replace the recipient and operating keys and therefore ultimately
controls the protected value. A compromised guardian quorum can take over after
the replacement delay. Loss of two guardians prevents replacement. A quorum
that is unavailable or malicious can block recovery to usable operation. This
authority is explicit; there is no claim that the chain can identify a rightful
owner after every accepted authority has been compromised.

C0 fixes the guardian root for the entire lifetime of a vault. Guardian-root
replacement, membership changes and lost-quorum rescue are out of scope. These
limits must be accepted or the candidate revised before contract implementation.

## Candidate state and transition table

State carries a vault identity, policy generation, current role keys, immutable
guardian root and security limits. Each transition spends exactly one protected
UTXO and creates exactly one positive output. A normal payout is the sole
intentional ordinary-address exit. All other outputs remain protected.

| Source | Action | Authority | Successor | Timing |
| --- | --- | --- | --- | --- |
| Idle | Initiate | `O` | Pending, same policy/generation | Creates a fresh pending UTXO |
| Pending | Execute | `O` | Exactly the current `P` P2PK | Normal relative delay from pending creation |
| Idle or Pending | Quarantine | `R` | Quarantine, same policy/generation | No relative delay |
| Idle, Pending or Quarantine | Stage routine replacement | `C` and `G` | Replacing, exact committed new role keys | Creates a fresh replacing UTXO |
| Idle, Pending or Quarantine | Stage emergency replacement | `G` | Replacing, exact committed new role keys | Creates a fresh replacing UTXO |
| Replacing | Finalize | Permissionless execution of the already authorized exact plan | Idle under replacement policy, generation incremented once | Routine/emergency relative delay from replacing creation |

Finalization has no authority to edit the plan, choose a recipient or create an
ordinary payout. The successor must use the reviewed C0 template, immutable root
and security limits. Routine replacement delay must be positive; emergency
replacement delay must be strictly longer. Normal withdrawal delay is also
positive. Actual constants and their operational response budgets are undecided.
DAA units are not exact elapsed-time promises.

No action starts a second replacement from Replacing, sends Quarantine directly
to P2PK, resets a pending clock in place, cancels replacement with an old role
key, or changes the guardian root. Once replacement is accepted, old `O`, `R`
and `C` cannot veto its finalization. Before acceptance, competing valid spends
still race; there is no guaranteed recovery or replacement priority.

An erroneous guardian-approved plan cannot be canceled in this candidate. After
its delay it must finalize to protected Idle before a new correction can be
staged. This prevents a compromised old key from vetoing recovery, but makes
guardian review and correct new-key possession essential. Cancellation and
guardian compromise rescue require a separately specified authority if added.

Normal Execute deliberately remains an exit from protected custody. A stolen
operating key can still request that fixed payout, subject to the waiting period
and recovery race. C0 does not claim protection for every subsequent spend by
the recipient. Protecting ordinary payments indefinitely is a separate design.

## Binding and conservation requirements

The model must distinguish the authorization statement from the actual script
enforcement. The eventual canonical authorization statement must bind:

1. Protocol/profile version, TN10 identity and vault identity.
2. Exact source transaction ID/index, source state and policy generation.
3. Action kind and current policy digest.
4. Full replacement role keys, successor template identity and next generation.
5. Fixed delay branch, value/fee policy and every permitted successor field.

Use two distinct guardian identities; duplicate copies of one signature do not
form a quorum. New-role possession checks must bind to the same plan and role.
Transaction signatures must commit to the intended transaction and sequence.
The exact encoding, signature domain and construction of a non-circular vault
identity are implementation gates, not already verified cryptographic formats.

For a transition with value `v` and fee `f`, output value is exactly `v - f > 0`
and `0 <= f <= max_fee`. The model must use integer sompi and reject malformed
or overflowing values. It must not permit an extra input/output, hidden change,
alternate output index, unauthorized state field or weaker successor template.

A per-transition cap does not bound lifetime fee loss. C0 therefore requires a
non-replenishing cumulative fee allowance and finite replacement count in its
initial model. Each transition deducts its actual fee; staging reserves enough
allowance for the permitted continuation, and finalization cannot reset either
counter. A pure model can represent these counters; enforceable native state
encoding is still unproved. Exhaustion can freeze value. Minimum relay fees may
change. Fee sponsorship, top-ups and emergency budget changes are excluded and
must be separately designed before any funded candidate is considered.

## Accepted-chain operation and rollback

Any future watcher must follow exact protected outpoints, policy generations
and accepted successor scripts. After a chain removal it must undo current
observations and reconcile before signing or reporting custody. A guardian
authorization or saved transaction from an orphaned branch does not itself
prove current eligibility. Preserve the exact saved transaction and durable
effect history; never clear it merely because an observation is reversed.

Unknown broadcasts require reconciliation, and a broadcast response never means
accepted custody. No watcher may infer owner intent from a valid owner
signature. Independent guardian/signer hosts, descriptor verification, backup
recovery and external alert delivery require their own operational acceptance.
Neither a local model nor two endpoint names demonstrate that independence.

## Core capability gap register

| Requirement | Candidate mechanism | Current disposition |
| --- | --- | --- |
| Fixed destination, amount and output constraints | Transaction introspection and covenant successor checks | Used by v1; C0 additions need new native tests |
| Fresh relative waiting period | New UTXO, sequence commitment and contextual age validation | Used by v1; replacement branch still unimplemented |
| Quorum approval | Distinct conventional signature checks over exact plan | Candidate; compile and test before claiming feasibility |
| Continued custody through replacement | Constrained successor template and policy generation | Candidate; template/encoding feasibility unresolved |
| Global fee and replacement budgets | State carried in the protected successor | Candidate; model and native enforcement unresolved |
| Guardian availability and legitimate intent | Independent authorized operators and review | Not supplied by a consensus opcode |
| Fast/reliable observation | Existing accepted-chain/UTXO APIs, with measured gaps if any | No new RPC requirement established |
| Secret storage and recipient key delivery | Separately reviewed private service | Not solved by public node validation |
| Post-quantum authorization | Separate end-to-end cryptographic design | No C0 or v1 guarantee; not a reason to invent an opcode yet |

Reference baseline: the exact node/compiler revisions in
[TOOLCHAIN.json](../TOOLCHAIN.json), upstream
[KIP-17](https://github.com/kaspanet/kips/blob/master/kip-0017.md) for scripting
and [KIP-16](https://github.com/kaspanet/kips/blob/master/kip-0016.md) for proof
verification. Proposal status, code presence and activation on a particular
network are separate facts. C0 adds no proof circuit or verifier integration.

A core gap must have a reproducible failing case against a pinned revision and
an explanation of why existing scripting cannot enforce the required rule.
If one is found, propose the narrowest general primitive, exact validation and
failure behavior, resource pricing, compatibility and activation. A local node
patch does not change the public network's rules. Extra RPC/indexing capability
should be separated from a consensus proposal.

## Adversarial acceptance cases

These are planned checks, not test results:

| Case | Required result or explicit limitation |
| --- | --- |
| Only `O` stolen | No arbitrary recipient, bypassed delay or direct replacement |
| `O`, `R`, `C` stolen; `G` secure | Quarantine/DoS remains possible; no guardian-free replacement; accepted replacement removes old roles |
| One guardian stolen or duplicated | Cannot reach quorum, including with any operational role signature |
| Guardian quorum stolen | Demonstrate eventual takeover; do not label the candidate all-key safe |
| Two guardians lost | Demonstrate replacement unavailability; do not claim lost-key rescue |
| Change vault/network/source/action/generation/recipient | Previously collected authorization rejected |
| Change plan after staging | Finalization rejected even with an otherwise valid old key |
| Routine/emergency early finalization | Native VM commitment checks and separate node age rejection required |
| Repeated stage/reset/cancel from Replacing | Rejected; original maturity anchor preserved |
| Weaken guardian root/delay/fee limit in successor | Rejected on every transition |
| Ordinary payout from Quarantine or Replacing | Rejected; recovery continues in protected custody |
| Normal payout then ordinary recipient spend | Demonstrate the intentional end of protection |
| Extra input/output, inflation, overflow, over-cap fee | Rejected, including output-index substitutions |
| Repeated quarantine/replacement cycle | Lifetime allowance/count never reset; exhaustion and freezes exposed |
| Reorg, stale observation, crash or ambiguous send | Reconcile exact state/outbox without claiming finality or resetting effects |

## Implementation gates and handoff

1. Review the C0 authority tradeoff, immutable guardians, intentional payout
   boundary, no-cancellation rule and exhaustion/lost-quorum freezes. Resolve
   any unacceptable outcome before building a contract.
2. Implement only an offline abstract state machine and the table above. Keep
   signatures/DAA/chain observations visibly abstract and publish counterexamples.
3. Specify canonical plan/state encoding, safe integer bounds, vault identity,
   possession proofs and successor-template construction. Demonstrate the
   compiler can represent every rule using the pinned TN10 primitives.
4. Add separate native VM fixtures and mutation tests. Check actual successor
   scripts, all authority paths, signature commitments, conservation and costs.
   No existing funded script or signer policy may be widened or relabeled.
5. If an enforcement gap survives, produce the failing native example and a
   scoped core proposal. Otherwise publish a covenant/policy standard and wallet
   integration plan without claiming a consensus change is necessary.
6. Only after review, verified independent custody and separate funded-pilot
   authorization, use fresh test-only keys and journals for TN10 acceptance.

This document supplies a candidate transition/authorization table and test
plan. It does not close the security target's design gates, establish native
enforcement, add a running service or change any current protection claim.
