# Recipient-encryption lab verification — October 19, 2026

Scope: `scripts/recipient_lab.py`, using the installed, pinned cryptography
50.0.2 HPKE implementation. Fictional data, disposable local identities and
temporary databases only. No RPC, real agency integration, R0 service or funds.

The 37 new Python tests cover:

- Intended-recipient decryption and failure with an unrelated private key;
  separate signing/delivery roles and rejection of low-order delivery keys.
- Context-bound encrypted enrollment challenges, signed possession responses,
  approver certificates, replay/restart, concurrency, expiry and bounded growth.
- Fresh encapsulations, exact record/certificate binding, wrong roles/domains,
  substituted keys/epochs/networks, ciphertext/tag corruption and malformed
  encapsulations, including changes re-signed by the correct authorities.
- Signature checks before decryption, strict schemas, duplicate JSON fields,
  integer/hex/size/time bounds and the maximum-size payload.
- Local receipt persistence and replay protection under concurrent connections;
  policy/role pinning and public transcript signature consistency.
- Explicit limits: independent databases can accept again; receipts can be
  signed without decryption; expiry does not stop direct decryption; later
  delivery-private-key compromise exposes recorded messages.

Current suite: **302 tests = 68 Rust + 234 Python** (previous 197 Python + 37).
The Python suite runs locally; full required GitHub CI also verifies native
tests, formatting, compiled fixtures, service templates, four local demos and
the native binary build. Exact workflow outcomes are attached to this milestone's
pull request. The local host has no Cargo toolchain.

[recipient-lab-demo.json](recipient-lab-demo.json) is a labeled public synthetic
transcript. Its local plaintext-match result is not public proof of decryption;
the signatures, bindings and zero-real-transactions label are independently
checked by the test suite. It includes no plaintext or private key.

This is not an independent audit, protected remote key delivery, quantum-safe
protocol or demonstration of government adoption. Read the
[protocol description and trust boundaries](../docs/RECIPIENT-ENCRYPTION-LAB.md).
