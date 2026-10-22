# Encrypted software keys for the PQ recipient experiment

`scripts/pq_locked_adapter.py` adds encrypted key storage to the
[experimental PQ message profile](POST-QUANTUM-RECIPIENT-PROFILE.md). Fresh
signing/delivery seeds are encrypted before any file publication. They never
pass through a plaintext temporary key file. The ordinary PQ test-key adapter
retains its existing storage format; there is no implicit migration or fallback.

This is experimental software protection for fictional data on a trusted POSIX
host. It is not a hardware keystore, independently reviewed release, native
Kaspa signature change, completed audit or overall quantum-safety claim.

## Storage format

| Field or boundary | Exact behavior |
| --- | --- |
| Key filename | Owner-only `keys.enc.json`, inside a fresh owner-only endpoint directory |
| Format | `icp-pq-endpoint-encrypted-software-keystore-v0` |
| Password KDF | Library Argon2id v19, 65,536 KiB memory, 3 iterations, 4 lanes, 32-byte result |
| Salt and nonce | Fresh random 16-byte salt and 12-byte AES-GCM nonce per encryption |
| Encryption | Library AES-256-GCM; full header is domain-separated associated data |
| Header binding | Exact format, PQ suite, KDF, AEAD, salt, nonce and public endpoint fingerprint |
| Public fingerprint | SHA-384 identifier of the role's exact PQ public record, 96 lowercase hexadecimal characters |
| Parsing bounds | 12 KiB keystore; 4 KiB decrypted record; fixed KDF parameters checked before derivation |
| Passphrase input | 16..1,024 exact bytes; no NUL/CR/LF, no whitespace-only value, no trimming or Unicode normalization |

The parameters match RFC 9106's lower-memory Argon2id recommendation; this
does not certify the application. Sixteen bytes is a length floor, not an
entropy guarantee. Choose a long, unpredictable passphrase and retain it
separately. A stolen file enables offline guesses; there is no password reset,
recovery escrow, hardware attempt counter or brute-force-proof claim.

Changing the header, ciphertext, public fingerprint or password causes rejection.
Unsupported algorithms fail closed. The locked adapter rejects a directory
containing `keys.json`, and the ordinary adapter cannot open a locked endpoint.
Public PQ records, policy pins and wire cryptography remain the same.

## CLI and reusable API

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_pq_locked_adapter.py' -v
python3 examples/pq_locked_file_exchange.py
python3 scripts/pq_locked_adapter.py --help
```

For interactive creation, use a terminal; the hidden prompt asks twice:

```bash
python3 scripts/pq_locked_adapter.py keygen \
  --endpoint .secrets/recipient-locked --role recipient \
  --output recipient-public.json
```

The parent `.secrets` directory must already exist with owner-only permissions.
The result includes the public endpoint fingerprint. Authenticate public records
and policy pins through a trusted channel. A fingerprint read from an untrusted
backup is not a trusted identity.

Use the [file adapter commands](RECIPIENT-FILE-ADAPTER.md), replacing the script
with `pq_locked_adapter.py`. Each private operation unlocks its own endpoint.
`policy` and `verify-receipt` need public material only and never prompt.
`public --endpoint PATH --output FILE` recovers a lost public export without
regenerating keys or altering acceptance history.

Automation can supply `--passphrase-fd N` **before the subcommand**. The FD must
refer to an owner-only regular file or pipe carrying exact raw bytes until EOF,
without a trailing newline. Reads have a 1,024-byte cap and a 10-second deadline.
No password argument, environment lookup or silent stdin fallback exists.
Unknown CLI arguments are rejected without echoing their values. TTY prompting
fails closed when hidden input is unavailable. The fictional process example
uses inherited anonymous pipes; it writes no password file.

Python applications can call `LockedEndpoint.create(path, role, password_bytes)`
and reopen with `LockedEndpoint(path, password_bytes)`. The inherited
`challenge`, `answer`, `bind`, `seal`, `approve`, `send`, `receive` and `receipt`
methods retain the existing PQ policy/role checks. Applications are responsible
for their password source, object lifetime and trusted process boundary.

## Backup and recovery boundaries

Two commands check **keys only**:

```bash
python3 scripts/pq_locked_adapter.py backup-key \
  --endpoint .secrets/recipient-locked --endpoint-id TRUSTED_ENDPOINT_ID \
  --output .secrets/recipient.icp-key-backup
python3 scripts/pq_locked_adapter.py check-backup \
  --input .secrets/recipient.icp-key-backup --endpoint-id TRUSTED_ENDPOINT_ID
```

`TRUSTED_ENDPOINT_ID` is the previously authenticated 96-character fingerprint.
The backup is a byte-identical encrypted key file, written privately with atomic
no-clobber publication. `check-backup` decrypts in memory and verifies its public
identity. Neither command copies, restores, resets or attests replay databases.
There is deliberately no endpoint-state restore or automatic migration command.

Locked endpoints also persist a separate owner-only `.icp-state-guard` marker
before initializing each policy database. Later opens require that marker,
the database, its bound policy/role and required tables. Missing, empty or
incomplete state is rejected instead of silently initializing it. A database
without its marker is not adopted. A crash during first initialization may
leave a marker without complete state and block further use; there is no reset
shortcut. Preserve the files for review rather than deleting them to retry.

After loss of the key file only, stop endpoint processes, validate the encrypted
backup against the independently trusted fingerprint, and restore that key file
without overwriting any existing file. Retain the original endpoint directory,
policy databases and guard markers. Tests exercise this exact case: the saved
receipt remains available and the earlier message still rejects as a replay.
If any acceptance state is missing or uncertain, key recovery alone does not
authorize resuming the old policy. Do not restore keys into an empty directory
and present it as continuity of the original endpoint.

Presence markers are local accident checks, not monotonic anti-rollback storage.
Deleting/copying/restoring the complete endpoint can defeat local replay history.
An old intact snapshot may accept again. Live-file mutation and concurrent
manual recovery remain outside the trusted-host model; stop processes first.
Receipt commit and plaintext export are still separate operations. Recover an
existing receipt after export failure; never reset history or reaccept to retry.

## What the demonstration establishes

Seventeen endpoint CLI processes and one separate ciphertext relay exchange a
fictional binary file on one host. Private operations unlock from pipes; wrong
password rejection precedes a successful receive. Receipt verification, replay
rejection after unlock, saved-receipt recovery and exact encrypted-key backup
verification pass. No plaintext key file or real transaction is produced.
See the [saved flags](../evidence/pq-keystore-demo.json) and
[verification record](../evidence/pq-keystore-verification.md).

This does not demonstrate remote authenticated transport, independent devices,
biometrics, secure enclaves, memory zeroization, swap/core-dump protection,
password recovery, key/passphrase rotation or global replay protection. An
unlocked or compromised host can read keys and plaintext. Earlier plaintext
copies are not erased or revoked. Full static delivery-key compromise still
exposes recorded ciphertext. Authenticated transport/identity, reviewed device
integration and independent protocol review remain ahead.

## Primary references

- [cryptography 50.0.2 Argon2 API](https://cryptography.io/en/50.0.2/hazmat/primitives/key-derivation-functions/)
- [RFC 9106, parameter choice](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)
- [cryptography 50.0.2 AESGCM API](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/)
