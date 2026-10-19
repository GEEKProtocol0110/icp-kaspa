# ICP architecture

[Project home](../README.md) · [Plain-English introduction](PLAIN-ENGLISH.md) · [Documentation](README.md)

Three parts work together: **the vault enforces withdrawal rules, the watchtower
checks requests, and a restricted signer authorizes recovery transactions.**
They currently run as an experimental Kaspa Testnet-10 prototype.

This page describes the technical boundaries. For an everyday example and
definitions, start with [ICP in plain English](PLAIN-ENGLISH.md). The complete
threat model and paper comparison are in [SECURITY-TARGET.md](SECURITY-TARGET.md).

## Separate data-access experiments

| Component | What exists | Boundary |
| --- | --- | --- |
| [Transfer lab](TRANSFER-LAB.md) | Local encrypted messages, signatures and recipient receipts | Keys are supplied separately; a receipt is a recipient claim |
| [Recipient lab](RECIPIENT-ENCRYPTION-LAB.md) | HPKE encryption to a distinct pinned delivery key, possession challenge and approver/sender/recipient signatures | One-host local experiment; no remote release, chain gating or quantum claim |
| [Anchor observer](TRANSFER-ANCHOR.md) | Exact signed-exchange commitment checked against trusted-node scans; a later [TN10 run](ICP-Transfer-Anchor-Live-Proof.md) supplies dated two-endpoint observations | Chain changes can withdraw that observation; it does not authorize key release |
| [Bound response lab](BOUND-RESPONSE-LAB.md) | HPKE enrollment and signed response records in checkpointed recovery | Encrypts random enrollment token only; response bundle remains unencrypted and non-secret |
| [Signed coordinator lab](SIGNED-COORDINATOR-LAB.md) | Two-role permission, recipient challenge and revocation signatures over checkpointed synthetic decisions | No real record validation, delivery-key proof, content keys, transport or native tickets |
| [Coordinator recovery model](RELEASE-COORDINATOR-MODEL.md) | Separate fake vault/ledger/delivery journals and independent fencing/checkpoints | Trusted one-host simulation with admission/authentication fixtures; no real keys or native tickets |
| [Release ledger](RELEASE-LEDGER-MODEL.md) | Permanent local grant/quota history, model signatures, two fake observations and non-secret placeholders | No native tickets or real key delivery; database copies are not fenced |

The [read-ticket/release draft](READ-TICKET-RELEASE-DRAFT.md) proposes a future
service connecting permission checks and decryption-key delivery. An ordinary
P2PK ticket would serve as a chain witness; the service would enforce access
rules and quotas. Used-grant and possible-disclosure history must survive
changes to chain observations. The complete release service is unimplemented.

The separate [release-service design](RELEASE-SERVICE-DESIGN.md) specifies
proposed content-key ownership, private response preparation, authoritative
commit and delivery boundaries. It adds cross-store recovery, revocation order
and independently maintained fencing/continuity requirements. These are design
requirements for a future service. The [coordinator model](RELEASE-COORDINATOR-MODEL.md)
now tests a bounded subset of its cross-store recovery and fencing rules with
non-secret placeholders; deployment enforcement and real delivery remain gates.

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
