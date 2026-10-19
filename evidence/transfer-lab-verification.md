# Local transfer lab verification

October 19, 2026 UTC. Additive offline experiment; custody contracts and policies
are unchanged. No RPC, chain anchoring, spending or funded session was used.

The local demo reports a matching synthetic plaintext after authenticated
decryption, successful verification of both exchange signatures and a matching
recipient receipt, and refusal of a second acceptance in the same database.
Its public transcript is [transfer-lab-demo.json](transfer-lab-demo.json).
No AES/private signing keys or plaintext are included. Signature verification
of this transcript does not independently prove the reported decryption.

## Verification

- `cargo fmt --check`: passed.
- `cargo test --locked --features live`: 62 tests passed.
- `python3 -m unittest discover -s tests -p 'test_*.py' -v`: 108 tests passed,
  including 29 transfer-lab checks; combined current count is 170.
- `python3 scripts/transfer_lab.py`: passed; failed integrated checks would exit
  unsuccessfully rather than only print a failure flag.
- Both checksum-pinned fixture compilers passed; custody artifacts unchanged.
- Exact lab dependency versions resolved as binary wheels. Shell/systemd,
  documentation-link, attribution and diff-whitespace checks passed.
- Workflow YAML parsed successfully, including the quoted binary-wheel command.

The new checks cover ciphertext/hash/tag tampering, valid re-signatures over
mismatched associated data, incorrect roles/keys, missing or exchanged role
signatures, policy/namespace binding, exact local-clock bounds, size/lifetime
limits, duplicate/unknown JSON fields, malformed hex, fresh keys/nonces/IDs,
restart and concurrent duplicate acceptance, independently reset DB scope,
policy drift, receipt substitution/status/signature changes and historical
receipt verification. The published fixed public transcript is also verified.

Three expected limitations are executable tests: a separate database can accept
the same exchange again, a recipient key holder can sign a matching receipt
without decrypting, and an AES key holder can decrypt outside the policy API.
Thus this experiment does not establish globally consumed
read tickets, global data velocity, remote execution or factual truth. The
permission clock and receipt time are local/trusted claims, not chain timestamps.

The cryptography package, cffi and pycparser versions are pinned for the lab.
Key transport is assumed out of band. The roles run in one process for the
demo, without enclave/OS isolation or a zeroization claim. There is no STARK
program, quantum-resistant authentication, production throughput benchmark or
independent audit. See [TRANSFER-LAB.md](../docs/TRANSFER-LAB.md) for its full
versioned encoding, crash/replay semantics and integration gates.
