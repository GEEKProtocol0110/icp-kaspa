# PQ recipient verification — October 22, 2026

## Change and scope

This adds a separate experimental recipient profile with library hybrid
ML-KEM-768/X25519 HPKE, ML-DSA-65 role signatures and SHA-384 commitments.
The conventional profile and all native Kaspa signatures, custody contracts,
funded-session records and pinned workers are unchanged. The
[profile guide](../docs/POST-QUANTUM-RECIPIENT-PROFILE.md) states the exact suite,
wire/storage formats and remaining trust boundaries. This is not an independent
audit, FIPS certification, quantum-hardware test or overall quantum-safety claim.

## Checks executed locally

| Check | Result |
| --- | --- |
| New PQ suite | 50 tests passed |
| Conventional recipient suites | 71 tests passed |
| PQ in-process cryptographic demo | Passed |
| PQ binary file/HTTP example | Passed; 15 endpoint CLI processes and one relay on one host |
| Full Python attempt | 788 discovered; 467 passed, 321 errors from unavailable native Rust workers |
| `cargo fmt --check` | Could not execute: this host has no cargo |
| `cargo test --locked --features live` | Could not execute: this host has no cargo |
| `git diff --check` | Passed |

The required [CI workflow](../.github/workflows/verify.yml) builds the native
workers and runs Rust formatting, locked Rust tests, the full Python suite and
both PQ demos. Its exact-head result must pass before merge; the local full-suite
attempt above is not a passing full suite. Inventory is 930 tests: 142 Rust and
788 Python. Consult the milestone PR/workflow for the final CI outcome.

## Adversarial boundaries exercised

- Both hybrid private components are required; either mismatched component
  causes authenticated decryption failure. Fresh encapsulations differ.
- ML-DSA-65 verifies the full canonical manifest with the exact purpose context.
  Legacy Ed25519, ML-DSA-44, missing/truncated signatures and wrong purposes fail.
- Low-order X25519 and malformed ML-KEM public components are rejected.
- Exact pinned suite/namespace/policy, role separation, certificate substitution
  rejection and cross-profile endpoint/envelope/database rejection in both
  directions. A simulated unsupported backend fails without a second attempt
  or conventional fallback.
- Re-signed altered metadata and mutated ciphertext with recomputed commitment
  still fail HPKE authentication. Invalid possession proofs do not consume a
  valid proof. Expiry, wrong keys and wrong roles reject.
- Exact 64 KiB payload boundary accounts for the larger wire size. Replay after
  restart and concurrent acceptance against one intact store yield one claim.
- Owner-only directories/key/state files, symlinks/special files, bounded reads,
  duplicate JSON fields, no-clobber output and CLI error secrecy.
- Failed plaintext export preserves the saved acceptance receipt and forbids
  another receive. Saved binding and receipt recovery do not reset state.
- Separate process exchange of a fictional binary message over actual loopback
  HTTP, matching plaintext and recipient signature, with replay/wrong-role
  rejection and byte-identical receipt recovery after restart.

The [saved flags](pq-recipient-demo.json) contain no private keys, plaintext,
endpoint paths, sensitive records or signed wallet transactions. They are
reproducible local assertions, not public proof of reading or execution.

## Reproduction and limits

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_pq_recipient.py' -v
python3 -m unittest discover -s tests -p 'test_recipient*.py' -v
python3 scripts/pq_recipient_lab.py
python3 examples/pq_recipient_file_exchange.py
```

All endpoints share a trusted host; TEST private-key files are unencrypted and
plaintext enters ordinary memory. No remote authenticated transport, device
keystore, rotation/recovery scheme, forward secrecy, global replay protection,
real permission source, chain gate or reviewed key-release service was tested.
Kaspa-native signatures retain their existing cryptography. Later full static
delivery-key compromise exposes recorded ciphertext; copied replay state can
accept again. Receipt persistence and file export are not atomic. Independent
protocol review and operational isolation remain necessary before sensitive use.
