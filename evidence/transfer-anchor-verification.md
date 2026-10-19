# Transfer anchor observer verification

October 19, 2026. New module: `scripts/transfer_anchor.py`.

28 new offline tests cover the exact signed-envelope/policy commitment, pinned
transaction ID, wrong/missing payload, accepted-chain-only evidence,
selected-chain successor thresholds, DAA non-equivalence, whole-page atomicity,
rollback/reacceptance, restart, pinned DB configuration, expiry/freshness,
sampled-sink pagination, wrong network/unhealthy node, malformed/duplicate
responses, processing budgets and read-only RPC failure/latency behavior.

The synthetic public demo reuses the previous signed local transcript. Its
fabricated chain changes first meet the successor threshold, then remove the
accepting block. The pinned output is `transfer-anchor-demo.json`; the test
compares it with freshly replayed results. No private keys or plaintext are
added to that output.

Local verification: all **136 Python tests** pass. The refreshed work host has
no Cargo/rustup executable; required `cargo fmt --check` and
`cargo test --locked --features live` are delegated to the repository's GitHub
verification workflow. The Rust sources and custody artifacts are unchanged.

This milestone has no live anchor transaction, funded run, independent-node
observation, SPV/consensus proof, audit or quantum-safety result. The observer
does not authorize receiver acceptance or release keys. See
`docs/TRANSFER-ANCHOR.md` for the full observation and trust rules.
