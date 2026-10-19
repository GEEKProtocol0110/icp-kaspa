# Protected recovery v1 - testnet prototype

This implementation is separate from the original v0 contract. It uses the same
pinned compiler and node revision. Existing deposits cannot migrate themselves;
v0 has no migration entrypoint. A funded v1 lifecycle is recorded in
[ICP-Protected-Recovery-Live-Proof.md](ICP-Protected-Recovery-Live-Proof.md);
that measured run supplements the native checks.

## Custody rules

Immutable public keys: owner, recovery trigger, normal recipient and cold
authority. All four must differ. The cold authority also owns the fixed final
cold payout address. Immutable limits: normal delay, strictly longer cold delay
and maximum fee. State is 0 (idle), 1 (pending) or 2 (quarantined).

| Source | Action | Required key | Destination | Relative sequence |
| --- | --- | --- | --- | --- |
| Idle | initiate | Owner | Same contract, pending | 0 |
| Pending | execute | Owner | Fixed normal recipient P2PK | Normal delay |
| Idle or pending | recover | Recovery trigger | Same contract, quarantined | 0 |
| Quarantined | release | Cold authority | Fixed cold P2PK | Cold delay |

Quarantine has no hot-key path, re-arm, repeated recover or policy rotation.
The recovery trigger cannot move funds directly to P2PK. The cold delay begins
at the new quarantined UTXO, regardless of deposit or pending age. Neither hot
authority can reset that clock or repeatedly consume fees. One input, one
positive output, no inflation and the immutable fee ceiling apply to every
path. At most three transitions occur per deposit (initiate, recover, release).

## Threat model

Once recovery is accepted, compromising both owner and recovery-trigger keys
still does not authorize release without the cold key. Before recovery is
accepted, the normal pending execution path remains possible; timely inclusion
still matters. A compromised trigger can force quarantine (denial of service)
but cannot release it. Lost cold authority makes quarantined value unavailable.

The cold authority is conventional Schnorr. If it is compromised, the cold delay
is the remaining restriction and there is no further rescue path. Final cold
P2PK value leaves the covenant on explicit cold release. This is neither a
recursive recovery tower nor a quantum-safe scheme. It is not independently
audited and has not been approved as production custody.

## Separate signer files

The new `icp-protected` CLI accepts exactly one explicit signer file per signing
command through `ICP_SIGNER_KEY_FILE`. Each file declares its network and one
role. The loader checks permissions, role and public-key equality against the
pinned public policy. Read-only commands and broadcasting need no signer.
There is no combined-key fallback and no reading of v0 `.secrets/keys.json`.

Generate roles separately on their intended hosts. Only public keys are needed
for policy setup. File separation on one machine is not host or process
isolation: deployment still needs OS access controls, independent devices and
an authenticated signer transport. Never put the cold file on the watcher host.

The watcher can pin v1's quarantined script as `recovery_spk`; recovery
confirmation then proves entry into quarantine, not cold payout or finality.
Its recovery-only signer cannot authorize `release`. A new watcher database is
required for the new descriptor. Cold release is an explicit operator
action and is never performed by the watcher.

## Build and public setup

```bash
python3 scripts/compile.py
python3 scripts/compile_protected.py --fixtures
cargo test --locked --features live
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo build --locked --features live
```

On the respective hosts (each command prints only its public key):

```bash
target/debug/icp-protected keygen owner .secrets/owner/key.json
target/debug/icp-protected keygen recovery .secrets/recovery/key.json
target/debug/icp-protected keygen recipient .secrets/recipient/key.json
target/debug/icp-protected keygen cold .secrets/cold/key.json
```

Create a public policy file from those four public outputs. Substitute the
64-character public-key hex strings; never insert private keys:

```json
{
  "version": "protected-v1",
  "network": "testnet-10",
  "owner": "<owner public key>",
  "recovery": "<recovery public key>",
  "recipient": "<recipient public key>",
  "cold": "<cold public key>",
  "delay_daa": 600,
  "cold_delay_daa": 1800,
  "max_fee": 2000000
}
```

These are test parameters, not a production response window. The CLI restricts
the fee cap to at most 0.02 test KAS. There is no fee estimator; live relay/mass
requirements may exceed that cap, requiring a new reviewed policy before
deposit. Do not blindly retry or alter an already-funded script's parameters.

```bash
target/debug/icp-protected setup public-policy.json
target/debug/icp-protected addresses
target/debug/icp-protected descriptor
```

`ICP_PROTECTED_STATE_DIR` selects a distinct session directory (default:
`runtime/protected`). `setup` refuses to replace an existing public policy.
Compilation failure preserves that policy; re-run `compile_protected.py` with
`--policy runtime/protected/public-policy.json --output runtime/protected`
after inspection. Setup and public artifacts are trusted operator inputs.
Keep them consistent across hosts and verify the full descriptor out of band.
The loader rejects different immutable templates across the three state files.

The following commands are the interface for a fresh session. The completed
funded acceptance run has its own journal and proof; do not rerun that directory:

```bash
ICP_SIGNER_KEY_FILE=.secrets/owner/key.json target/debug/icp-protected deposit 30000000
ICP_SIGNER_KEY_FILE=.secrets/owner/key.json target/debug/icp-protected prepare-initiate DEPOSIT_TXID:0
```

The v1 deposit creates one vault output and funding change. The owner key
also signs funding; the recipient key is never needed for vault operations.
The normal payout requires `execute PENDING_TXID:0` after the normal delay.

On the recovery host, with only its recovery-trigger secret present:

```bash
ICP_SIGNER_KEY_FILE=.secrets/recovery/key.json python3 scripts/watchtower.py arm --cli target/debug/icp-protected --db runtime/protected/watch.sqlite --config runtime/protected/watch-config.json --deposit DEPOSIT_TXID:0
ICP_SIGNER_KEY_FILE=.secrets/recovery/key.json python3 scripts/watchtower.py run --cli target/debug/icp-protected --db runtime/protected/watch.sqlite --config runtime/protected/watch-config.json --execute
```

Authorize intended withdrawals before broadcast using that same `--db` and
`--config`, as in WATCHTOWER.md. The automatic recovery only prepares/signs with
the recovery role. A quarantine outpoint may be released deliberately from the
cold host:

```bash
ICP_SIGNER_KEY_FILE=.secrets/cold/key.json target/debug/icp-protected prepare-release QUARANTINE_TXID:0
target/debug/icp-protected broadcast runtime/protected/PREPARED_RECEIPT.json
```

Cold preparation currently needs a TN10 RPC connection to retrieve the exact
UTXO; air-gapped signing and an authenticated remote signer protocol remain
future work. Preparing a sequence-locked transaction before maturity is
possible, but the node must reject early broadcast. A native VM cannot prove
actual UTXO age. The recorded pilot demonstrated explicit early rejection and
later acceptance for both exits, plus a second-node output check. It did not
induce a public-network reorganization or outage.

The fixed cold P2PK payout remains an explicit exit, not indefinite protection.
There is no key rotation, lost-key rescue or cold-stage emergency cancellation.
All fixture keys in `artifacts/protected/` and the VM tests are public and must
never receive funds. The v0 live receipts do not establish v1 acceptance.

## Automated pilot

`scripts/protected_pilot.py` orchestrates the two-deposit run using a fresh
`runtime/protected-pilot/session`, separate `.secrets/protected-pilot/ROLE/key.json`
files, and a confirmed 0.70-test-KAS funding output. Its funding receipt must be
`runtime/protected-pilot/funding-receipt.json`. Public setup and private-key
backup must happen before funding. It refuses an existing journal; after any
unknown outcome, reconcile the recorded IDs and exact UTXOs before acting.

The optional `fund_protected_pilot` Cargo example reads an explicit public plan:
`policy` (path), `source_public_key`, `source_outpoint`, `source_amount`, `amount`
and `receipt` (new path). Its one donor role file is selected explicitly with
`ICP_SIGNER_KEY_FILE`; it never reads a combined legacy key bundle. It permits
one pinned test-only P2PK source of at most 1 test KAS and funds only the owner
in that new policy. It requires `ICP_RPC_URL` or the existing proxy wrapper.
Build with `cargo build --locked --features live --example fund_protected_pilot`.
The pilot runs via `python3 scripts/protected_pilot.py` (or the proxy wrapper).
Its public evidence omits signature scripts and signed outbox payloads; raw
receipts, SQLite state and role keys stay in the private session backup.
