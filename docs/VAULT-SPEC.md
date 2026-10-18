# ICP vault 0.0.0 - prototype specification

Engineering proposal derived from the supplied ICP v2 paper. These choices are
not attributed to, or claimed to be approved by, its author.

## Security target

With only the owner spending key compromised, an attacker cannot bypass a fresh
pending-withdrawal delay, change the pinned payout/recovery destinations, or
extract value beyond the per-transition fee bound. A separately secure recovery
key can move the entire remainder to the fixed recovery address. Watcher
availability, fee adequacy, and inclusion before competing execution are
assumptions. At maturity execution and recovery race; recovery has no priority.

This prototype uses conventional Schnorr signatures. It does not claim quantum
security. Compromise or forgery of the recovery key permits immediate transfer
to the recovery address, whose conventional key may also be compromised. That
is outside the security target. No STARK, data release, enclave or STATIC
settlement functionality is present.

## Parameters and state

Immutable: owner pubkey, recovery pubkey, recipient pubkey, delay in DAA units,
maximum fee in sompi. State: pending boolean. Use distinct keys for the three
roles. The test harness uses public deterministic fixtures only; never fund
fixture addresses. The live operator must generate fresh test-only keys.

| Input state | Entrypoint | Authority | Output | Timing |
| --- | --- | --- | --- | --- |
| Idle | initiate | owner signature | Same template, pending=true | No delay |
| Pending | execute | owner signature | Fixed recipient P2PK | CSV >= delay_daa |
| Idle or Pending | recover | recovery signature | Fixed recovery P2PK | No delay |

Every transition has exactly one input and exactly one output. The active input
must be zero. The sole output is positive, cannot exceed input value, and retains
at least input minus max_fee. No partial withdrawals, arbitrary destinations,
batching, migration, rotation, or idle->idle loop exists. All parameters must
remain pinned across initiation; validateOutputState enforces the successor
template and complete state. Fees can be paid from vault value at most twice
along an initiate->execute/recover lifecycle. Oversized/dust outputs and mass
are additionally subject to node consensus and mempool rules.

## Delay and cancellation

The pending output is a new UTXO. The old deposit's age is irrelevant. CSV checks
the input sequence commitment; actual age is enforced by UTXO-context consensus
validation. Script-engine success alone cannot prove wall-clock maturity or
node acceptance. Test both the script condition and node age rejection.

Recovery exits custody into a fixed P2PK address; this is a limited prototype
choice, not the paper's recursive cold citadel. Recovering into an additional
covenant and quantum-safe authority require separate specification.

## Watcher policy

Observe accepted chain changes, not just the mempool. Match the exact deposit
outpoint and pinned contract. For any unexpected idle->pending spend, alert and
prepare recovery. An operator explicitly authorizes expected pending outpoints
out of band. A stolen owner signature is never treated as proof of owner intent.
Track removals/reorganizations and restore spent-state observations. Never
release irreversible off-chain secrets based on this watcher.

## Testnet acceptance gate

Before calling this deployed: pin compiler and node; verify the exact connected
network and covenant activation; generate fresh test-only keys; compile exact
parameters; record deposit, initiate, early rejection, delayed execution and
recovery transaction IDs; independently observe their accepted-chain status.
Separate deposits exercise execution and recovery. A successful broadcast is
not confirmation. Keep failed transactions and node error responses as evidence.

Native VM tests exercise real compiled bytecode but do not mine blocks, prove
DAA age, measure fees/mass or constitute a security audit.
