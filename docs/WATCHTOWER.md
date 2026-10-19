# Watchtower prototype

The watchtower follows Kaspa's accepted virtual chain through VSPC v2, records
its cursor and tracked vault UTXOs in SQLite, and undoes tracked changes when
the node reports removed chain blocks. It uses a trusted, synced, UTXO-indexed
testnet-10 node; it is not an SPV or full consensus verifier.

## Withdrawal policy

Register exact idle deposit outpoints. An owner signature alone never makes a
withdrawal approved. Approval must bind the registered deposit, the exact
pending transaction ID/output zero, and an acceptance DAA deadline. An approval
is checked against the accepting chain block's DAA score. An approved intent
retains that decision for its lifetime on that branch; a reorganization causes
re-evaluation when the intent is accepted again.

Use preparation to authorize an intent before broadcasting:

```bash
bin/icp prepare-initiate DEPOSIT_TXID:INDEX
python3 scripts/watchtower.py authorize --deposit DEPOSIT_TXID:INDEX --pending PREPARED_TXID:0 --expires-daa DAA_DEADLINE
bin/icp broadcast runtime/PREPARED_RECEIPT.json
```

The local approval database is itself a trusted operator authority. Keep it
separate from an attacker-accessible owner wallet in a real deployment. The
current test harness keeps all roles on one host and does not provide that
production separation.

## Arm and run

```bash
python3 scripts/watchtower.py arm --deposit DEPOSIT_TXID:0 --deposit DEPOSIT_TXID:1
python3 scripts/watchtower.py run --execute
```

Arming checks that registered deposits are still exact unspent idle-vault
outputs before and after taking the chain anchor. A changed or already-pending
deposit cannot be silently bootstrapped. `run` without `--execute` is dry-run
mode. `--once` processes one fetched chain response, including its local
batches; the response may still end before the sampled chain target. In restricted
environments wrap the command with `scripts/with_proxy.py` and a reachable TN10
Borsh TLS endpoint.

Unexpected pending withdrawals cause the signer adapter to prepare recovery.
The controller validates the source outpoint, fixed recovery destination,
positive output amount and fee bound, then commits the signed transaction to
a durable outbox before broadcasting it. Repeated broadcasts use that same
transaction, not a new value-consuming recovery sequence.

The controller never reads private keys directly. The current native signer
does use the test key file; separating the signer into another process/host
with restricted recovery-only credentials remains deployment work.

## Reconciliation and limits

- Mempool acceptance means SUBMITTED. Only a matching accepted-chain recovery
  transition makes an action CONFIRMED.
- Every signing/retry pass first checks the exact current pending UTXO. A spent
  or orphaned UTXO is not blindly rebroadcast.
- A broadcast timeout leaves its signed outbox durable. After a restart the
  chain is scanned before retrying the same bytes.
- Retries are spaced by at least ten seconds and bounded at three attempts.
  An exhausted or fee-rejected action requires operator attention.
- Removing an initiation block orphans its recovery action. Removing a recovery
  block restores the pending state and rearms the existing outbox.
- A reorganization below the bootstrap anchor stops the watcher for explicit
  reconciliation. Missing history, incomplete RPC pages, stale cursors, changed
  configuration or unhealthy nodes cannot silently advance its cursor.
- Accepted unauthorized payout is reported as a critical failure, never as a
  successful recovery. At maturity, recovery has no guaranteed spend priority.

Alerts and action history are stored in the SQLite audit table. The CLI emits
audit events to stdout for an operator/supervisor to collect. No external
messaging integration or unattended hosted service is configured.

There is no guaranteed response SLA. The live demo measures actual detection
and recovery; outages can consume the entire 600-DAA delay. RPC backlogs,
pruning, database retention, signer isolation and production monitoring require
additional operational work and review.

## Bounded catch-up

Rebuild both native CLIs and update the Python watcher together. Native `scan`
now samples the node's sink before fetching VSPC v2 changes and returns it as
`target`. Older binaries without that field are rejected. The pinned node can
truncate a VSPC page without a `hasMore` flag; a drained page alone cannot prove
that the watcher is current.

The watcher preflights list completeness, hash ordering and budgets before any
commit, applies all removals atomically, and then commits bounded batches of
whole accepted blocks. Recovery reconciliation runs after every committed
batch, with the existing exact live pending-UTXO check before signing/retry.
The original RPC observation time is retained across cached batches, so a long
drain does not manufacture a fresh heartbeat.

| Option | Default | Maximum | Meaning |
| --- | --- | --- | --- |
| `--max-blocks` | 128 | 4,096 | Accepted blocks per local transaction batch |
| `--max-transactions` | 10,000 | 1,000,000 | Accepted transactions per local batch; blocks are never split |
| `--max-removed` | 2,048 | 100,000 | Removals allowed in the first atomic batch |

An oversized individual block or removal set stops for review; nothing is
silently truncated. Reorgs below the bootstrap anchor still stop. Inspect
history and the resource implications before increasing a limit. A malformed
envelope fails before the first commit; a later invalid vault transition can
leave earlier valid batches committed, with the durable cursor and outbox
available for reconciliation and restart.

`scan_progress` records the sampled target, whether it was reached, and local
remaining block/transaction counts. Health reports `CHAIN_BACKLOG` while local
blocks remain or the sampled target has not been reached. Backlog causes an
immediate next fetch without the normal polling sleep. An empty response that
does not reach its target stops rather than spinning or claiming success. A
target displaced by concurrent reorganization can require another scan or
explicit review; these observations do not establish finality.

Audit stdout delivery reads at most 256 records per committed batch and saves
its cursor only after successful writes. Delivery is at least once: a crash
after writing but before saving can repeat events. Consumers should deduplicate
on `event_id`. Remaining audit records drain on subsequent batches/scans.

These are **local processing bounds**, not caps on RPC response bytes, memory,
RPC/signing latency, total DB/undo history or recovery-candidate count. There
is no response SLA or automatic pruning/deep-history reconstruction. See
[chain-batching verification](../evidence/chain-batching-verification.md).

## Verification

`tests/test_watchtower.py` exercises approvals, expiry, malformed/incomplete
responses, wrong networks, restart reconciliation, retry bounds, redirected
signer responses and both initiation/recovery reorganizations. Native script
tests remain distinct from these controller tests.

The optional `scripts/watchtower_pilot.py` spends existing test funds into a
fresh two-vault deposit. It approves one prepared intent, leaves the other
unapproved, runs the actual observer/recovery loop, then executes the approved
withdrawal only after its delay. It refuses to overwrite an existing pilot
directory. Inspect a partial journal before taking further action.

## Candidate protected recovery

Select `--cli target/debug/icp-protected` explicitly and use a fresh `--db`
and `--config`; the default remains the live-tested v0 CLI. The v1 descriptor's
recovery script is the quarantined covenant. Its terminal recovery record adds
`custody: QUARANTINED`, outpoint and amount, and emits `RECOVERY_QUARANTINED`.
The exact quarantine outpoint remains in the tracked outputs with stage
`quarantined`. A later accepted spend must retain the value/fee/layout bounds
and pay the descriptor's fixed cold script. The watcher then records
`custody: COLD_RELEASED`, release transaction/outpoint, amount and acceptance DAA,
and emits `COLD_RELEASE_OBSERVED`. The original recovery transaction ID remains
unchanged so its outbox stays CONFIRMED. Removing the release block restores
quarantine; removing recovery as well restores the pending recovery action.

Cold release is observed, not approved or signed by the watcher. Its cold key
and actual relative age are enforced by the existing covenant and trusted
node. Final P2PK spends are outside this watcher's custody tracking. Health
reports include branch-current `quarantined_outputs` and
`cold_releases_observed` counts; these do not establish independent finality.

An older database may contain a QUARANTINED terminal record without its tracked
output. This version refuses that state rather than inventing missed cold
history. Health reports `QUARANTINE_TRACKING_INCOMPLETE`. Preserve a SQLite
backup and reconcile accepted-chain history from before recovery under operator
review; do not delete the database, edit it to pass checks, or assume arming
from the current tip reconstructs past releases. Old rollback snapshots with
the same gap also stop atomically for reconciliation.

See [PROTECTED-RECOVERY.md](PROTECTED-RECOVERY.md)
for signer roles and setup. The existing funded pilot script is v0 only.
