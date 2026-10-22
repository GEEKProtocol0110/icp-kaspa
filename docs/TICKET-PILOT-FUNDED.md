# Funded P0 preparation — October 22, 2026

Two separate Testnet-10 pilots have reached **signed issuance, before network
submission**. Both exact funding sources passed fresh paired observations under
the [repaired reader](TICKET-PILOT-READ-PATH.md). Each signing intent was saved
privately before key access. The complete signed records were then checked
again by the native verifier and preserved with their journals, independent
authorities, shared source claims, observer stores and pinned binaries.

Both operators are stopped pending explicit approval for submission. The final
journal inspection found two source claims, two signed issuance outboxes, zero
submission intents, zero terminal choices and zero terminal signatures. A later
read from both configured nodes still reported both exact 24,000,000-sompi
funding sources as unspent. The total remains 0.48 test KAS at that recheck;
no pilot fee was spent. This is dated evidence, not a continuing balance claim.

The [public record](../evidence/ticket-pilot-funded-preparation.json) contains
public source/transaction IDs, output addresses, outbox digests and the later
funding reads. It excludes keys, signature scripts, signed RPC records and
private stores. An ID or digest does not establish transaction acceptance.

## Proposed submission scope

Only Testnet-10 test coins are involved. The existing native reviews define:

| Run | First transaction | One later transaction | Maximum pilot fee |
| --- | --- | --- | --- |
| Consume | Issue from its 0.24 test KAS source: 0.12 to its ticket key, 0.10 change to its funding key | Consume that ticket: 0.10 to its return key | 0.04 test KAS |
| Unused refund | Issue from its separate 0.24 test KAS source: 0.12 to its ticket key, 0.10 change to its funding key | Refund that unused ticket: 0.10 to its return key | 0.04 test KAS |

Four transactions together have a fee ceiling of 8,000,000 sompi (0.08 test KAS),
excluding initial funding fees. The terminal IDs in the public record are
unsigned previews; neither terminal branch has been chosen or signed. On
successful completion, the planned funding change and return outputs would
total 0.40 test KAS. This plan is not evidence that those outputs exist.

## Resume from the saved state

After explicit approval and review of the code gate, recover the existing
journals and exact signed issuance records. Do not start a new source claim or
re-sign either issuance. Keep the pinned native binaries and the preselected
thirty-second binding policy, thirty-second observer age and ten successors.
Recovery requires fresh paired observations; saved reports are historical.
A stale history cursor or a reorg across the bootstrap can still block progress.
Do not relabel an old observer or silently reset its history.

Before every permitted submission, save its permanent intent and checkpoint,
then recheck current eligibility. Any intent, including a rejected, failed or
unknown result, permits read-only reconciliation only. Never repeat a send.
A transport acceptance response is not confirmation: observe exact native
transactions and outputs through both pinned node views before proceeding.
Choose and prepare only the reviewed terminal branch after issuance is observed.

## Verification and limits

The merged reader repair passed 140 Rust and 695 Python tests locally. Both
final-head CI runs passed at commit `27d5316d7e8e215bdb9287c3409bf60788a15911`,
merged as `ccfdf663783d55d99bbde489d329504efb68828e`. No implementation changed
during this funded preparation checkpoint. Both saved issuances passed another
native VM/integrity verification after the operators stopped.

This establishes local preparation using live trusted-node source observations.
It establishes no funded ticket acceptance, actual permission, data-key release,
independent signer enforcement or quantum-security guarantee. Host, node,
clock, code and store trust remain. The private checkpoint is a forensic backup;
jointly restoring authorities/claims and component journals is not safe recovery.
