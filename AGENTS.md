# ICP development

- This is Internal Command Protocol, separate from Geek Protocol.
- Testnet-10 only. Never add a mainnet switch as a routine change.
- Read PROJECT-STATUS.md and docs/VAULT-SPEC.md before changing custody rules.
- Keep .secrets/, runtime/, signed outboxes, databases and private session backups out of Git.
- Public test fixtures deliberately use known keys; never fund them.
- An owner signature is not evidence of legitimate withdrawal intent.
- Preserve chain rollback, exact outpoint checks and the durable recovery outbox.
- A broadcast response is not confirmation. Confirm exact accepted-chain outputs.
- Run cargo fmt --check, cargo test --locked --features live and the Python unittest suite.
- Live tests require a separate journal and must reconcile failed or unknown outcomes before retrying.
- Keep receipts, limitations and the project checkpoint current; do not claim quantum safety or audit completion.
