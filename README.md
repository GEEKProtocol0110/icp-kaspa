# Internal Command Protocol (ICP)

[![Verify ICP prototype](https://github.com/GEEKProtocol0110/icp-kaspa/actions/workflows/verify.yml/badge.svg)](https://github.com/GEEKProtocol0110/icp-kaspa/actions/workflows/verify.yml)

Open-source Kaspa testnet vault and watchtower prototype. Concept by CrypTony;
implementation developed with Michael Gee. Original implementation: [MIT](LICENSE).

A small Kaspa covenant vault derived from the ICP whitepaper. This is a separate
project from Geek Protocol. Engineering choices are documented in
[the specification](docs/VAULT-SPEC.md).

**Status:** the v0 vault/watchtower and protected-v1 recovery lifecycle passed
funded testnet-10 runs. V1 kept recovery inside a quarantine covenant and
released it with a separate cold key after a new delay. Both early payouts
were sequence-rejected; the exact same signed transactions later passed.
[Protected recovery proof](docs/ICP-Protected-Recovery-Live-Proof.md),
[earlier watchtower proof](docs/ICP-Watchtower-Live-Proof.md) and
[v0 vault proof](docs/ICP-Testnet-Live-Proof.md) include transaction IDs.
All 85 offline checks pass. GitHub Actions reproduces them on pushes and pull
requests. This remains an experimental testnet prototype without an independent
security audit or production signer isolation.

## What works locally

- Owner-signed initiation creates a new pending UTXO.
- Pending execution requires a relative DAA lock and pays a fixed recipient.
- A separate recovery signature sends the remainder to a fixed recovery address.
- Every path enforces one input, one output, positive value and a fee ceiling.
- Native tests execute actual compiled bytecode with compute-budget limits.
- The operator CLI builds, signs, checks and submits transactions, recording
  prepared, mempool-accepted, rejected/unknown, and UTXO-observation evidence.
- The live acceptance harness automates two deposits' lifecycles after funding:
  initiation, an explicit early-execution rejection, recovery and delayed payout.

## Reproduce

Linux x86_64, Python 3, the pinned Rust 1.99.1 toolchain and a C compiler are required. Use a
Linux Codespace if needed. All Rust dependencies are commit-pinned and locked.

```bash
python3 scripts/compile.py
python3 scripts/compile_protected.py --fixtures
cargo test --locked --features live
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo build --locked --features live
```

The compiler bootstrap verifies both the release archive and executable SHA-256.
The upstream v1.0.0 release still emits compiler/artifact version 0.1.0; its
source pragma must match that value. The exact upstream commits and checksums
are in [TOOLCHAIN.json](TOOLCHAIN.json).

## Run a fresh testnet session

Build the CLI with `cargo build --locked --features live`, then use
`target/debug/icp`. The separately saved prototype archive also includes a
Linux x86_64 `bin/icp`; executables are not tracked in this repository.
The source excludes all live session keys.

```bash
./target/debug/icp init
./target/debug/icp node
```

`init` generates fresh test-only keys into `.secrets/keys.json` with restrictive
permissions on Unix, compiles both vault states, and prints public addresses.
It refuses to overwrite existing keys. Fund the printed **funding address** with
3 test KAS on **testnet-10**, then run:

```bash
python3 scripts/pilot.py
```

The live runner accepts only a synced, UTXO-indexed TN10 node past the pinned
covenant activation. A testnet address alone does not identify TN10 versus TN12.
No mainnet option is provided. `ICP_RPC_URL` optionally specifies a Borsh wRPC
endpoint; otherwise the official SDK resolver is used. For restricted environments, install the optional
`websockets==16.0` package and use `python3 scripts/with_proxy.py target/debug/icp status`
or `python3 scripts/with_proxy.py python3 scripts/pilot.py`. The wrapper uses
the environment's normal proxy. `ICP_UPSTREAM_URL` optionally supplies a
previously resolved TN10 Borsh TLS endpoint when HTTP resolver access fails. Node identity/status is checked again before each broadcast.

The CLI's default fee is 0.02 test KAS per transaction; each deposit UTXO is
1 test KAS. Delay is 600 DAA-score units, approximately a minute at 10 BPS,
with no wall-clock guarantee. The node decides maturity.

The automated pilot refuses to restart over an existing `runtime/pilot.json`.
If interrupted, inspect the saved transaction IDs and live UTXOs before taking
further action. Direct recovery and inspection commands remain available:

```bash
./target/debug/icp status
./target/debug/icp initiate TXID:INDEX
./target/debug/icp execute TXID:INDEX
./target/debug/icp recover TXID:INDEX
```

## Evidence and important limits

Public fixture keys in `artifacts/` and the test source are intentionally known.
**Never fund fixture addresses.** Fresh live keys are separate. Do not publish
`.secrets/` or put real funds in any key created by this test harness. All roles
share a host here for testing; production separation is not provided.

The native VM checks the relative-sequence requirement; actual UTXO age is a
separate node consensus check. Native pass results alone do not prove node acceptance. The live evidence
separately establishes acceptance for the exact tested transactions and fee
settings. Other values, nodes and network conditions need their own checks.
Broadcast receipts are not confirmations. The pilot observes exact outpoints
in the node's accepted-chain UTXO view; that observation can change after a
reorganization. Recovery does not have guaranteed priority at maturity.

The watchtower implementation and operator instructions are in
[docs/WATCHTOWER.md](docs/WATCHTOWER.md). Protected recovery covenants, authority
rotation, arbitrary payout recipients, partial withdrawal, data-release
tickets, DAG Zippers, proof systems, post-quantum authority and STATIC trading
are outside this initial prototype. The specification defines the watcher
requirements for the next milestone.

## Develop and contribute

```bash
git clone https://github.com/GEEKProtocol0110/icp-kaspa.git
cd icp-kaspa
```

Read [PROJECT-STATUS.md](PROJECT-STATUS.md), [AGENTS.md](AGENTS.md) and the
specification before changing custody behavior. No live RPC, signing or private
test data is required by CI. Open an issue or pull request with reproducible
evidence; do not include keys or funded-session backups.

Next: production signer isolation, cold-stage rescue/rotation,
service operation and external review. See [the project checkpoint](docs/ICP-Project-Handoff.md).
Pre-publication Git history is preserved in [the import record](docs/IMPORT.md).

The original implementation is MIT licensed. Third-party dependencies and
source papers retain their own terms; see [NOTICE.md](NOTICE.md).

## Protected recovery v1

The additive [v1 implementation](docs/PROTECTED-RECOVERY.md) moves recovery into a
quarantined covenant. Release requires an independent cold key and a new,
longer relative delay. Its `icp-protected` CLI uses one explicit role-specific
signer file, with no combined-key fallback. Read-only operations need no keys.

Build its public fixtures with `python3 scripts/compile_protected.py --fixtures`
before running Cargo tests. The original v0 contract and CLI remain available;
their live receipts do not cover v1. Its own funded acceptance run is recorded
in the protected recovery proof above. The automated harness is
`scripts/protected_pilot.py`; it refuses an existing journal. Production signer
isolation and cold-stage rescue/rotation remain work.
