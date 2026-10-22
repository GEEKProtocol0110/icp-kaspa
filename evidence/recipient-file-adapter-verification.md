# Recipient file/bytes adapter verification — October 22, 2026

## Change and scope

The existing recipient HPKE/signature experiment now has endpoint-owned test
keys, a reusable Python bytes API and a file CLI. No encryption primitives,
suite, existing wire namespace, custody contract or live pilot policy changed.
The [guide](../docs/RECIPIENT-FILE-ADAPTER.md) defines the pinning, filesystem,
size, receipt/export and trust boundaries. This is not an independent audit.

## Checks executed locally

| Check | Result |
| --- | --- |
| New adapter suite | 29 tests passed |
| Existing recipient cryptography suite | 37 tests passed |
| Ciphertext relay suite | 5 tests passed |
| Separate-process fictional binary-file example | Passed; 15 endpoint CLI processes plus one loopback HTTP relay on one host |
| Full Python suite attempt | 738 discovered; 417 passed, 321 errors caused by missing native Rust worker binaries |
| `cargo fmt --check` | Could not execute: this local host has no `cargo` |
| `cargo test --locked --features live` | Could not execute: this local host has no `cargo` |
| `git diff --check` | Passed |

The required GitHub workflow builds those native workers and runs formatting,
locked Rust tests, the complete Python suite and all demos. Exact-head CI must
pass before merge. Check the milestone PR/workflow for its actual outcome;
the local attempt above is not represented as a passing full suite.

## Adversarial coverage

- Separate signing and delivery keys, with delivery private material present
  only in the recipient endpoint; unrelated recipients and wrong roles fail.
- Explicit policy fingerprint, namespace/suite/network checks, role substitution
  rejection and duplicate signing-role rejection.
- Ciphertext mutation, expiry, empty/oversize payloads, exact 64 KiB boundary
  and independently verifiable recipient receipt signatures.
- Replay after endpoint restart and two concurrent acceptances against one
  intact database, with one successful local receipt claim.
- Endpoint/key/database permissions, symlink endpoint/key/state rejection,
  FIFO/special-file rejection, bounded reads and duplicate-key JSON rejection.
- Atomic private file publication, existing-output and symlink no-clobber rules,
  no leaked temporary output, and suppressed private input in CLI failures.
- Output collision before acceptance, plus an explicit export-failure test
  after acceptance: the receipt remains recoverable, output may be absent,
  and another receive remains rejected. No exactly-once delivery is claimed.
- Real loopback HTTP upload/download through a separate relay process receiving
  ciphertext only; exact opaque bytes, immutable one-object limit, malformed
  transport identifier, unknown/path-traversal route, size and transfer-encoding
  rejection. The relay cannot bind publicly and serves no filesystem paths.

## Reproduction

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_recipient_adapter.py' -v
python3 -m unittest discover -s tests -p 'test_recipient_lab.py' -v
python3 examples/recipient_file_exchange.py
```

The [saved example result](recipient-file-adapter-demo.json) contains only
fictional-run result flags. It holds no private keys, plaintext, endpoint paths,
signed wallet transaction or real agency data. It is a local assertion, not
public cryptographic proof of decryption or reading.

## Remaining boundaries

Only file/bytes and loopback HTTP handoff were tested, on one trusted host with
conventional unencrypted test-key files. No remote transport, TLS endpoint, device keystore,
independent host isolation, key rotation/recovery, stream/chunking format,
chain-gated key delivery, real authorization integration, quantum protection
or production readiness was demonstrated. Static recipient-key compromise
exposes history; copied/restored databases can accept again. Existing funded
P0 sources, pinned workers and private journals were not opened or changed.
