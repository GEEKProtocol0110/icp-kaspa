# Journaled TN10 anchor pilot

`examples/prepare_transfer_anchor.rs` prepares one fixed-fee, self-returning
native P2PK transaction carrying the [transfer commitment](TRANSFER-ANCHOR.md).
`scripts/transfer_anchor_pilot.py` journals one submission and requires fresh
accepted-chain observations from two pinned endpoints. This is a test harness,
not an access-control or key-release service.

The preparer checks a healthy indexed TN10 node, exact live outpoint, amount,
P2PK script, absence of a covenant binding and non-coinbase status. It loads only
the pinned owner role file, commits storage mass and verifies the resulting
Schnorr signature with the native VM. One input returns to the same P2PK key;
the fixed fee is 2,000,000 sompi (0.02 test KAS). Sources are limited to 0.12–1
test KAS. There is no arbitrary destination or mainnet option. The preparer
never broadcasts.

The public funding policy uses the existing protected-v1 descriptor format to
reuse the role-key loader. The **funding input is ordinary P2PK**, not a vault
transition. The descriptor's withdrawal/recovery delays do not apply to it.
Custody contracts and their existing session state are unchanged.

## Build and configure

```bash
cargo build --locked --features live --bins --example prepare_transfer_anchor
python3 -m unittest discover -s tests -p 'test_transfer_anchor_pilot.py' -v
```

The verified CI workflow also publishes a short-lived `tn10-anchor-binaries`
artifact with the two binaries and SHA-256 checksums. Match the workflow's
commit to the reviewed source before using it. Binaries contain no live keys.

Keep a public configuration outside tracked source:

```json
{
  "network": "testnet-10",
  "funding": {
    "policy": {"description": "complete public protected-v1 policy with funding key as owner"},
    "source_outpoint": "64-lowercase-hex-transaction-id:0",
    "source_amount": 30000000
  },
  "nodes": [
    "wss://first-host/kaspa/testnet-10/wrpc/borsh",
    "wss://second-host/kaspa/testnet-10/wrpc/borsh"
  ]
}
```

The policy and outpoint strings above are placeholders. Read-only funding lookup:
run `prepare_transfer_anchor utxos PUBLIC_KEY` through `scripts/with_proxy.py`
with `ICP_UPSTREAM_URL` set to the chosen endpoint. Check the exact source
against both nodes. Never fund public fixture keys. Back up the actual test
key privately before use. `ICP_SIGNER_KEY_FILE` identifies its private role file
only in the preparation subprocess; reads and broadcasting strip that variable.

To start a new authorized test run from the repo root:

```bash
python3 scripts/transfer_anchor_pilot.py run runtime/anchor-config.json anchor-run-001
```

The pilot creates `runtime/anchor-run-001/` exclusively and refuses an existing
directory. It preflights both endpoints, creates a fresh disposable encrypted
lab transcript using synthetic plaintext, records both bootstrap hashes and
pins the exact commitment. No symmetric key or disposable private identity is
persisted. Funding keys are never copied into the run.

The native preparer exclusively creates and fsyncs `prepared.json`. The pilot
checks its on-disk plan, source, payload, layout, output and fee, then durably
writes `SUBMITTING` **before** making exactly one broadcast call. A mempool
response records `SUBMITTED_NOT_CONFIRMED`; it does not pass the gate.
The run also claims its exact funding outpoint in `runtime/transfer-anchor-claims/`
before preparation, blocking another run from silently reusing that source.
Claims are not cleared automatically, including on failures.

Both node scans run concurrently with independent cursors/SQLite databases.
Raw responses and local fetch-start times are saved under exclusive scan names.
The observer verifies exact accepted input/output layout as well as the pinned
transaction and payload. Success requires both reports to be fresh, caught up,
active under the local clock and at least 10 selected-chain successors beyond
their respective accepting block. The state is `TWO_NODE_ANCHOR_OBSERVED`.
This threshold remains uncalibrated; neither it nor two endpoints proves
finality or independent operator ownership.

## Stop and reconcile

Any ambiguous submission is `SUBMISSION_UNKNOWN`. Observation failures become
`OBSERVATION_INCOMPLETE`, retaining the original signed transaction and source
claim. The process group is terminated on subprocess timeout; a transaction may
already have reached the node. No automatic rebroadcast or replacement follows.

Resume **reads only**, using the same configuration and run:

```bash
python3 scripts/transfer_anchor_pilot.py observe runtime/anchor-config.json anchor-run-001
```

`observe` cannot sign or broadcast. It retains the original bootstraps and
continues from committed cursors. Changed configuration, payload, funding pins
or endpoints are refused. Expired permission, missing/pruned history, rollback
below bootstrap, a crash between saving scans and advancing the journal, or
corrupt local state require explicit reconciliation. Do not remove a source
claim or start a replacement until the original transaction and exact source
outpoint have been reconciled on both nodes. Historical inspection after expiry
must remain labeled historical; it cannot produce a currently active grant.

## Evidence and boundary

Publish only reviewed public transaction/scan/transcript data and dated results.
Exclude role files, paths to private sessions, SQLite databases and operational
journals from Git. A live result must state its exact transaction, payload,
output, fee, endpoints, observation times and limits separately from synthetic
fixtures. This harness proves no remote execution, factual truth, protected
key delivery, read-ticket consumption, quantum safety or production readiness.
