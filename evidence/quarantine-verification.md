# Quarantine custody tracking verification

October 19, 2026. Controller/health/pilot observation update; custody contracts
and immutable policy rules are unchanged. No new funded run was performed.

- Both checksum-pinned compiler bootstraps: passed. Compiled artifacts unchanged.
- `cargo fmt --check`: passed.
- `cargo test --locked --features live`: 59 passed (3 network, 27 v0 VM,
  20 protected VM, 8 role/policy and 1 public CLI).
- `python3 -m unittest discover -s tests -p 'test_*.py' -v`: 60 passed,
  including 14 new quarantine/controller checks and the existing 46 checks.
- Shell wrapper syntax and systemd unit verification: passed.
- Working-tree diff whitespace check: passed.

The new tests cover exact quarantine outpoints; cold release fields; preserved
recovery confirmation; wrong destination, loop, amount and layout rejection;
pending/idle attempts to bypass quarantine; release and recovery reorganizations;
replacement cold exits; persistence across restart; legacy-state and legacy-undo
refusal; health counts; cold descriptor validation; and the explicit boundary
that later final P2PK spends are not observed.

These are synthetic accepted-chain controller inputs plus the existing native
VM suites. They are not a new live TN10 cold-release proof, an induced public
network reorganization, independent-host isolation or an external audit. The
trusted node remains responsible for actual UTXO-age enforcement. The fresh
pilot now requires its exact cold exit in watcher state before success; neither
completed historical pilot directory was rerun. Prior live proofs remain dated
historical observations, not validation of every new operational path.

Upgrades must preserve and inspect old SQLite state. A previously terminal
QUARANTINED record without its tracked output is refused rather than silently
synthesizing history. Review WATCHTOWER.md before running against existing funds.
