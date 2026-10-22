# PQ software keystore verification — October 22, 2026

## Scope

The [locked adapter](../docs/PQ-ENCRYPTED-KEYSTORE.md) adds fresh encrypted
software endpoints to the existing PQ message profile. Library Argon2id derives
the AES-256-GCM key from a passphrase; authenticated metadata fixes the format,
KDF, suite and public identity. Secrets are encrypted before file publication.
The ordinary PQ/conventional adapters retain their storage and wire behavior.
No native signature, custody rule, funded journal or pinned worker changed.
This is not an independent audit, hardware keystore or quantum-safety claim.

## Local checks

| Check | Result |
| --- | --- |
| New locked software endpoint suite | 39 tests passed |
| Existing PQ recipient suite | 50 tests passed |
| Conventional recipient suites | 71 tests passed |
| Separate-process encrypted-key exchange | Passed; 17 endpoint CLI processes, one loopback relay |
| Full Python suite attempt | 827 discovered: 506 passed, 321 errors from missing native Rust workers |
| `cargo fmt --check` | Could not execute: cargo is absent on this host |
| `cargo test --locked --features live` | Could not execute: cargo is absent on this host |
| `git diff --check` | Passed |

Inventory is 969 tests (142 Rust + 827 Python). The required
[workflow](../.github/workflows/verify.yml) builds native workers and runs Rust
formatting, locked Rust tests, the full Python suite and all demos. Its exact-head
result must pass before merge. Consult the milestone PR/workflow for the final
CI result; the local full-suite attempt is not represented as a passing suite.

## Security boundaries checked

- Fresh encrypted keys for all three roles, same public identity after unlock,
  no ordinary `keys.json` or plaintext temporary key file, owner-only storage.
- Wrong password, modified ciphertext/header/salt/nonce/identity, duplicate or
  missing JSON fields, bad size/encoding and unknown profile all reject.
- Changed or excessive KDF parameters reject before derivation; unsupported
  Argon2id rejects without fallback. Same-key encryption has fresh salt/nonce.
- Exact password length/input bounds; TTY confirmation and hidden-input failure;
  owner-only file/pipe FD, EOF, deadline, special-file rejection, no implicit stdin
  or environment lookup. Invalid argument errors do not echo a supplied secret.
- Encrypted key backup identity pins, exact private no-clobber export, wrong
  password/pin rejection, swapped endpoint rejection and no DB mutation.
- Public export recovery without rekeying; ordinary/locked key directories
  cannot be implicitly migrated, and mixed plaintext/locked directories reject.
- Receipt recovery after restoring only the checked encrypted key into the
  original intact endpoint. Original DB bytes remain unchanged, the saved
  receipt matches and the earlier message still rejects as replay.
- Per-policy durable presence markers: missing DB, missing marker, empty or
  incomplete DB, altered marker, unsafe permissions and symlink markers reject
  without silently recreating acceptance state. Concurrent first acceptance
  produces one successful local claim.
- Actual fictional binary exchange through separate role CLI processes and an
  opaque loopback relay; wrong unlock followed by successful receive, signature
  verification, replay rejection after unlock and byte-identical saved receipt.

The [saved flags](pq-keystore-demo.json) contain no keys, passwords, plaintext,
endpoint paths or wallet transactions. They are reproducible local assertions,
not public proof of reading, authorization, device isolation or chain activity.

## Reproduction and limits

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_pq_locked_adapter.py' -v
python3 -m unittest discover -s tests -p 'test_pq_recipient.py' -v
python3 -m unittest discover -s tests -p 'test_recipient*.py' -v
python3 examples/pq_locked_file_exchange.py
```

Passphrase entropy limits protection against offline guessing. Unlocked keys and
plaintext enter ordinary memory; hardware isolation, swap/core-dump protection,
zeroization and hostile-host security were not demonstrated. There is no password
reset, passphrase/key rotation, complete-state restore, rollback detection for
intact old snapshots or global replay protection. A crash during initial DB setup
can leave a blocking marker; do not delete it to retry. Keys-only recovery cannot
authorize resuming missing/uncertain acceptance state. Stop processes before any
manual key-file recovery. Receipt persistence and plaintext export remain
non-atomic. No remote authenticated transport or independent protocol review is
claimed. Native Kaspa cryptography and earlier private funded sessions are unchanged.
