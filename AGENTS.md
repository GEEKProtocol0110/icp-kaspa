# ICP development

- This is the standalone Internal Command Protocol project.
- Use project-level attribution. Do not add personal names, contact details or
  unrelated project affiliations. Preserve upstream legal notices and use
  repository-relative links in project documentation.
- Testnet-10 only. Never add a mainnet switch as a routine change.
- Read PROJECT-STATUS.md and docs/VAULT-SPEC.md before changing custody rules.
- Read docs/SECURITY-TARGET.md and the relevant v0/v1 specification. Keep the
  current compromise model separate from proposed stronger authorization rules.
- Keep .secrets/, runtime/, signed outboxes, databases and private session backups out of Git.
- Public test fixtures deliberately use known keys; never fund them.
- An owner signature is not evidence of legitimate withdrawal intent.
- Preserve chain rollback, exact outpoint checks and the durable recovery outbox.
- A broadcast response is not confirmation. Confirm exact accepted-chain outputs.
- Run cargo fmt --check, cargo test --locked --features live and the Python unittest suite.
- Install requirements-lab.txt before the full Python suite. The transfer lab
  is local-only: do not treat its signed receipt as a chain or execution proof.
- Live tests require a separate journal and must reconcile failed or unknown outcomes before retrying.
- Keep receipts, limitations and the project checkpoint current; do not claim quantum safety or audit completion.
