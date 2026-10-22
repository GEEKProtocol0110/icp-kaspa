# P0 submission journal verification

This milestone adds a private submission component to the observation-bound P0
controller under a distinct policy. It reserves one attempt before a simulated
effect and refuses retries after every durable intent, including timeout,
reported rejection and process death before the effect. Reconciliation reads
current paired tracker facts and never creates a signature or transport call.

The 38 new Python tests exercise exact signed-RPC dispatch, intent ordering,
unknown/malformed/rejected replies, stale or changed input metadata, writer
fencing, expiry/reorg after reservation, accepted replies without chain evidence,
exact issue/consume/refund observations, opposite-branch rejection, reorg rollback,
key-free outbox recovery and explicit fresh-handle reconciliation after restart.
They also cover actual process deaths after component commit and after an effect
marker, lost reply checkpoints, private/submission component restores, missing
stores, changed transport policy, variant reuse and native outbox corruption.

Tests use temporary unfunded keys, real offline native signatures and VM checks,
fabricated node pages and a simulated transport. There were no live P0 RPC calls,
operational keys, funding requests, P0 broadcasts or data-key deliveries.

Two counterexamples are intentional: a view change after the final sample can
precede the effect, and restoring the authority with all private stores can lose
the attempt and repeat identical bytes. Direct key/worker/transport access
bypasses the local controller. The nodes, clock, code, registry and independent
authority remain trusted; endpoint hostnames do not prove independent operators.

Validation inventory: 764 tests (126 Rust + 638 Python). Required verification
includes the full locked Rust suite, complete Python suite, formatting, both
contract compilers, public-review stability, existing demos, documentation links,
source checksums and privacy checks. Final-head CI must pass before merge.

See [the guide](../docs/TICKET-PILOT-SUBMISSION.md) for API sequence, storage
separation, reply/observation scope and the remaining live-transport milestone.
