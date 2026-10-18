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
mode. `--once` performs one chain scan and reconciliation pass. In restricted
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
