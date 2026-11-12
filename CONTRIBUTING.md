# Contributing to ICP

Internal Command Protocol (ICP) is an experimental Kaspa Testnet-10 research prototype. It is not a launched product, and it has not completed an independent security audit. Contributions are welcome when they keep that scope and the recorded limits honest.

## Before you start

- Use a GitHub issue for a reproducible bug or a clearly scoped proposal.
- Do not open a public issue for an unpatched vulnerability. Follow [SECURITY.md](SECURITY.md).
- Read [AGENTS.md](AGENTS.md) and the specification you intend to change. For custody rules, also read [PROJECT-STATUS.md](PROJECT-STATUS.md), [docs/VAULT-SPEC.md](docs/VAULT-SPEC.md), and [docs/SECURITY-TARGET.md](docs/SECURITY-TARGET.md).
- Stay on Testnet-10. Do not add a mainnet switch as a routine change.
- Keep `.secrets/`, `runtime/`, signed outboxes, databases, and private session backups out of Git.
- Public fixture keys are intentionally known. Never fund fixture addresses. Do not send seed phrases or private keys.
- Use project-level attribution. Preserve upstream legal notices.

## Checks

Use Linux x86_64, Python 3.11 or newer, a C compiler, and the pinned Rust toolchain in [rust-toolchain.toml](rust-toolchain.toml) (1.99.1, with rustfmt). From the repository root:

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/compile.py
python3 scripts/compile_protected.py --fixtures
cargo fmt --check
cargo test --locked --features live
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`cargo test --locked --features live` is the offline suite. It does not need a live RPC endpoint or private keys. Optional proxy runs can install [requirements-proxy.txt](requirements-proxy.txt); the full Python suite uses `requirements-lab.txt`.

[`.github/workflows/verify.yml`](.github/workflows/verify.yml) also builds the documented examples, runs the local labs, and checks the deployment unit files. The transfer lab is local-only. Do not treat its signed receipt as a chain or execution proof. A funded testnet session needs its own journal. Reconcile a failed or unknown outcome before retrying. A broadcast response is not confirmation.

## Pull requests

1. Branch from current `main`.
2. Keep the change small enough to review, and say what you actually ran.
3. Update the relevant specification, evidence note, or [PROJECT-STATUS.md](PROJECT-STATUS.md) when behavior or a stated limit changes.
4. Do not claim quantum safety, mainnet readiness, or a completed independent audit.

Accepted pull requests are squash-merged. Passing CI is required for the checks above. It is not an independent audit.

By contributing, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Code contributions are licensed under the MIT License in [LICENSE](LICENSE). Dependencies and source papers keep their own terms; see [NOTICE.md](NOTICE.md).
