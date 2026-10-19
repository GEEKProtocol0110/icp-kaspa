# ICP architecture

ICP combines on-chain custody constraints with an off-chain observer and a
restricted recovery signer. The current network is Kaspa Testnet-10.

The broader custody/data-access direction, compromise matrix and source-paper
mapping are in [SECURITY-TARGET.md](SECURITY-TARGET.md). The separate
[transfer lab](TRANSFER-LAB.md) implements a local encrypted manifest/receipt
experiment. On-chain data access and protected key release remain proposed
subsystems rather than implemented services.

The companion [transfer anchor observer](TRANSFER-ANCHOR.md) consumes the same
native scan envelope in a separate database. It pins the exact signed exchange
commitment/transaction, follows reorgs and checks selected-chain successors,
sampled-target catch-up and local freshness. It supplies no signing, key release
or receiver acceptance gate. A [funded TN10 run](ICP-Transfer-Anchor-Live-Proof.md)
adds dated two-endpoint observations alongside the synthetic fixtures.

## Responsibilities and trust

| Component | Responsibility | Boundary |
| --- | --- | --- |
| Vault covenant | Enforce allowed paths, fixed policy, layout and fee/value bounds | Does not identify legitimate human intent |
| Indexed TN10 node | Supply accepted-chain changes, live UTXOs and actual-age enforcement | Trusted by this prototype; no independent consensus verification |
| Watchtower + SQLite | Match exact outpoints, compare explicit approvals, track custody and chain rollback | Approval database and node configuration are trusted |
| Recovery signer | Sign only the pinned recovery path | Independent-host installation is still pending |
| Cold authority | Release quarantined value after its longer delay | Separate key; no cold-stage rescue or rotation yet |
| Supervisor/health probe | Restart services and expose operational problems | External alert delivery is not configured |

## Protected-v1 on-chain policy

The owner can initiate a withdrawal, creating a **new pending UTXO**. After its
relative DAA delay, the owner can execute to the fixed recipient. The recovery
authority can move idle or pending value into a quarantine covenant. The
quarantine accepts only cold-key release to the fixed cold script after a new,
longer delay. Each path enforces one input, one positive output and its fee cap.

The owner cannot reset a pending clock or redirect a payout. Recovery cannot
return to the hot states. Both normal and cold P2PK exits end covenant protection;
their later spends are outside the watcher's custody tracking. See
[the v1 specification](PROTECTED-RECOVERY.md) for exact invariants.

## Observation and action

1. Arm against exact unspent idle deposit outpoints, with a checked chain anchor.
2. Fetch VSPC v2 accepted-chain changes from the durable cursor. The native CLI
   samples the node's sink first and includes that target in the scan envelope.
3. Preflight page ordering, completeness and processing budgets. Undo all
   reported removals atomically, then commit bounded batches of accepted blocks.
4. After each committed batch, reconcile recovery. Before signing or retrying,
   check the exact **currently unspent** pending outpoint against the live node.
5. Validate a prepared recovery and commit its signed bytes to the durable
   outbox before broadcast. Retries reuse those bytes. Only matching accepted
   chain transitions confirm recovery.
6. Track protected quarantine through exact cold release. Preserve the original
   recovery confirmation; cold release has separate custody fields. Reorgs
   restore the prior branch state and reconcile the same recovery outbox.

These steps describe implementation behavior, not a guaranteed reaction time.
Between-batch checks may include node and signer calls. RPC response bytes,
database history and the number of recovery candidates are not bounded by the
local chain-processing budgets.

## Catch-up and failure semantics

The pinned node may paginate a VSPC response without a `hasMore` flag. Reaching
the end of a local page does not prove the watcher reached the sampled sink.
Progress records both remaining local blocks and whether the target was
reached. `CHAIN_BACKLOG` stays unhealthy until both conditions clear. During
backlog the watcher fetches again without its normal polling delay.

Each committed prefix includes its cursor and progress. A restart fetches from
that cursor, retaining outbox bytes and rollback history. A malformed page
envelope is rejected before any prefix is committed. A later semantic failure
can leave an earlier valid prefix committed; processing stops for operator
review. Excessive removals, an oversized individual block, missing history or
a reorg below the anchor stop processing rather than discard evidence.

Read [WATCHTOWER.md](WATCHTOWER.md) for budgets, legacy database requirements
and operator commands. Upgrade native binaries and the Python watcher together.

## Deployment boundary

The recovery-only SSH kit separates public policy, watcher state and signer
credentials. It pins the host key and descriptor, checks the live pending UTXO
independently at the signer, and exposes no arbitrary command, broadcast or
cold-release capability. Current funded evidence used role files on one test
host; offline SSH protocol tests do not establish independent-host isolation.
See [SIGNER-DEPLOYMENT.md](SIGNER-DEPLOYMENT.md).
