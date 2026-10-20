# Build and run on Testnet-10

[Project home](../README.md) · [Plain-English introduction](PLAIN-ENGLISH.md) · [Documentation](README.md)

This is the developer guide. It starts with offline checks, then explains a
fresh testnet session. To understand the project without installing anything,
read the plain-English introduction.

Start with offline verification. Public fixture keys are intentionally known:
**never fund fixture addresses**. Generate fresh test-only keys for a live run.
Keep `.secrets/`, `runtime/`, signed outboxes and databases out of Git.

## Reproduce the build

Use Linux x86_64, Python 3.11+, a C compiler and the pinned Rust 1.99.1 toolchain.
From the checkout root:

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/compile.py
python3 scripts/compile_protected.py --fixtures
cargo fmt --check
cargo test --locked --features live
cargo build --locked --features live --example native_ticket_worker --example ticket_read --example ticket_pilot_review --example ticket_pilot_private
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo build --locked --features live
```

Compiler bootstrap verifies the release archive and executable SHA-256. The
upstream v1.0.0 release emits compiler/artifact version 0.1.0; the source pragma
matches that value. Exact upstream commits and checksums are in
[TOOLCHAIN.json](../TOOLCHAIN.json). No live RPC or private keys are needed by CI.

## Fresh v0 session

The source excludes live session keys and does not track executables. Use the
freshly built binary:

```bash
./target/debug/icp init
./target/debug/icp node
```

`init` generates test-only keys into `.secrets/keys.json`, with restrictive
Unix permissions, compiles both v0 states and prints public addresses. It
refuses to overwrite existing keys. Fund the printed **funding address** with
3 test KAS on **testnet-10**, then run:

```bash
python3 scripts/pilot.py
```

The pilot uses two deposits to demonstrate recovery and delayed payout,
including explicit early-execution rejection. Its default fee is 0.02 test KAS
per transaction; each deposit is 1 test KAS. The delay is 600 DAA-score units,
approximately a minute at 10 BPS, with no wall-clock guarantee. The node decides
actual maturity.

The runner accepts only a synced, UTXO-indexed TN10 node past the pinned
covenant activation. A testnet address alone cannot distinguish TN10 and TN12.
There is no mainnet switch. Node identity is rechecked before each broadcast.

## Network configuration

`ICP_RPC_URL` optionally selects a Borsh wRPC endpoint; otherwise the official
SDK resolver is used. In restricted environments, install the optional
`websockets==16.0` package and use the environment's normal proxy:

```bash
python3 scripts/with_proxy.py target/debug/icp status
python3 scripts/with_proxy.py python3 scripts/pilot.py
```

`ICP_UPSTREAM_URL` can supply a previously resolved TN10 Borsh TLS endpoint if
HTTP resolver access fails. It does not bypass the native network guard.

## Inspect before retrying

The automated pilot refuses an existing `runtime/pilot.json`. If interrupted,
inspect its transaction IDs and live UTXOs; do not rerun over an ambiguous
outcome. Direct commands remain available:

```bash
./target/debug/icp status
./target/debug/icp initiate TXID:INDEX
./target/debug/icp execute TXID:INDEX
./target/debug/icp recover TXID:INDEX
```

A broadcast receipt is not confirmation. Exact accepted-chain output
observations can change after a reorganization. Native VM sequence checks do
not establish actual UTXO age or node acceptance. All roles share a host in
this pilot; it does not demonstrate production isolation.

## Protected-v1 and watchtower setup

V1 uses `target/debug/icp-protected`, a pinned policy and **one explicit
role-specific signer file**; no combined-key fallback. Read-only commands need
no keys. Follow [PROTECTED-RECOVERY.md](PROTECTED-RECOVERY.md) for role setup and
`scripts/protected_pilot.py` for its separately journaled acceptance harness.
It refuses an existing journal. V0 deposits are not migrated by selecting v1.

For approval, arming and monitoring, read [WATCHTOWER.md](WATCHTOWER.md). Select
the protected CLI explicitly with fresh watcher DB/config paths. Existing
quarantine-tracking gaps require history reconciliation before upgrade. Rebuild
the native CLI when upgrading to the scan-target/catch-up protocol.

For the recovery-only SSH endpoint, service accounts, supervision and health,
read [SIGNER-DEPLOYMENT.md](SIGNER-DEPLOYMENT.md). Separate-host operation and
external alerts still require installation and live acceptance.
