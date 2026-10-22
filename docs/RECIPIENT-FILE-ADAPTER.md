# Recipient encryption: file/bytes integration adapter

[Project home](../README.md) · [Recipient cryptography](RECIPIENT-ENCRYPTION-LAB.md)

The adapter makes the existing recipient experiment callable from separate
sender, approver and recipient processes. It accepts arbitrary binary bytes
within the existing **1..65,536-byte** limit. Public enrollment records and a
signed encrypted envelope can be copied through a transport without giving
that transport a private key. A recipient saves a signed acknowledgment.

This is an experimental file/bytes interface, not an installed universal
network protocol. Its namespace remains `icp-recipient-lab-v0`, with
`LOCAL_ONLY_RECIPIENT_ENCRYPTION_NO_CHAIN` explicitly preserved. Existing
HPKE, signatures, possession challenges and receipt checks are reused without
changing the cryptographic construction or treating old R0/P0 grants as access.

## Run the complete example

From the repository root, on a POSIX host with Python 3.12:

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 examples/recipient_file_exchange.py
python3 -m unittest discover -s tests -p 'test_recipient_adapter.py' -v
```

The example generates three fresh role directories in temporary storage and
starts separate CLI processes for every operation. It transfers a fictional
binary payload containing non-text bytes, checks byte-for-byte recovery,
verifies the receipt, rejects replay and the wrong role, then reopens the
recipient endpoint and recovers the exact saved receipt. It prints only public
result flags. A separate loopback HTTP relay process transports one encrypted
envelope without receiving key paths, private keys or plaintext. All temporary
private material is removed at the end, without a secure-erasure claim. No
external network connection or blockchain transaction occurs.

Separate processes on one host **do not establish independent-device or
operating-system isolation**. The [saved result](../evidence/recipient-file-adapter-demo.json)
is a local test report, not independent proof that decryption occurred.

The [example relay](../examples/recipient_ciphertext_relay.py) binds only to
`127.0.0.1` on an ephemeral port. It keeps at most one bounded immutable opaque
object in memory, checks its SHA-256 transport identifier and exposes no file
paths or directory listing. It has no TLS, user authentication, durable storage,
availability guarantee or public bind option. It is not a deployment service.
Endpoint signature/decryption checks remain necessary even after a matching
transport hash; a relay hash does not establish sender identity or authorization.

## Endpoint ownership and public enrollment

`scripts/recipient_adapter.py keygen --role ROLE --endpoint PRIVATE_DIRECTORY
--output PUBLIC_RECORD.json` creates a new endpoint. Roles are `sender`,
`approver` and `recipient`. Each owns one Ed25519 signing key. Only the recipient
owns the separate X25519 delivery private key. Creating an existing endpoint
fails rather than overwriting its keys.

Endpoint directories must be owner-only (`0700` or stricter); key and state files
must be owner-only (`0600` or stricter). Final-path symlinks, special input files,
overlarge reads and duplicate JSON keys are rejected. Keys are **unencrypted
test-only files in ordinary process memory**, not a protected device keystore.
Use fictional data. Do not distribute endpoint directories, `keys.json`, SQLite
files or their backups. Each intended deployment needs reviewed device-local
key storage, backup/recovery and host protection first.

The public records contain only role names and public keys. The operator must
authenticate them through a separate trusted channel. Building a policy from
untrusted records does not establish a person's identity.

```bash
python3 scripts/recipient_adapter.py policy \
  --approver approver-public.json --sender sender-public.json \
  --recipient recipient-public.json --output policy.json
```

This prints the public `policy_id`. Authenticate that fingerprint independently
and pin it at every endpoint. Every later command requires both `--policy
policy.json` and `--policy-id EXPECTED_FINGERPRINT`. Never blindly copy a pin
from an untrusted message alongside its replacement policy. There is no
automatic directory, key rotation, revocation, recovery or suite negotiation.

## Handoff sequence

Every command below also takes the two policy arguments, the owning
`--endpoint`, and a fresh `--output` path. Files must have existing parent
directories. All output files are private (`0600`) and never overwrite a path.

| Command | Owning endpoint | Input / result |
| --- | --- | --- |
| `challenge` | Approver | Saves an encrypted, 60-second delivery-key possession challenge |
| `answer --input challenge.json` | Recipient | Signs the answer using its identity and delivery keys |
| `bind --input proof.json` | Approver | Consumes the challenge and saves a public binding certificate |
| `binding` | Approver | Recovers that saved certificate if exporting it was interrupted |
| `seal --binding binding.json --input payload.bin` | Sender | Encrypts bytes to the pinned delivery key; fresh envelope per call |
| `approve --input sealed.json` | Approver | Approves the exact encrypted manifest |
| `send --input approved.json` | Sender | Adds the sender signature; produces the transferable envelope |
| `receive --input envelope.json --receipt receipt.json` | Recipient | Authenticates, decrypts, commits local acceptance and writes plaintext to `--output` |
| `receipt --transfer-id ID` | Recipient | Recovers the saved receipt without decrypting or accepting again |

To verify a recipient's acknowledgment, no private endpoint is needed:

```bash
python3 scripts/recipient_adapter.py verify-receipt \
  --policy policy.json --policy-id EXPECTED_FINGERPRINT \
  --input envelope.json --receipt receipt.json
```

The approver authenticates the manifest, not the truth of the encrypted content.
The receipt is a signed claim by the recipient key holder, not proof of reading,
real-world identity, execution, deletion or a Kaspa confirmation. Original file
names and MIME types are not transmitted or interpreted. No received bytes are
executed or automatically opened.

## Embed the bytes interface

`recipient_adapter.Endpoint` supplies the same operations to a Python caller.
`Endpoint.seal(policy, binding, payload_bytes, now)` returns a ciphertext
envelope; approval and sending remain separate operations. Transfer the canonical
envelope bytes through the application's existing transport. The recipient
calls `Endpoint.receive(policy, envelope_bytes, now)` and gets plaintext bytes
plus the signed receipt only after the local replay claim is committed.

The caller must authenticate/pin the policy, bound input bytes before parsing,
supply trusted time and keep role endpoints private. Import it from the
repository's `scripts` directory; there is no packaged/public API stability
promise. The executable [example](../examples/recipient_file_exchange.py)
shows the complete command contract and checks actual process return codes.

## Failure and confidentiality boundaries

- A relay/file copier gets ciphertext and visible metadata, not the delivery
  private key. The sender already knows the plaintext. Recipient-key compromise
  exposes recorded messages; there is no forward secrecy or quantum-safety claim.
- The intact recipient database rejects replay across processes/restarts and
  resolves concurrent acceptance to one receipt. Copies/restores can accept
  again. It is not a global use counter or rollback-proof service.
- The SQLite receipt commits **before** plaintext is returned. Output publication
  is not atomic with that commit. A crash/export failure may leave a receipt
  without an output file. Recover the receipt; do not erase/reset the database
  or claim that a second receive is authorized. This adapter has no automatic
  plaintext redelivery or exactly-once network-delivery claim.
- Output prechecks catch ordinary collisions before acceptance; atomic no-clobber
  writes prevent replacing files even if a collision happens afterward. CLI
  failures suppress input/exception details so secrets are not printed.
- Public keys, timing, lengths and labels remain visible. Expiry is a trusted
  local API check; it cannot revoke bytes already obtained by a key holder.
- There is no deployable remote service, large-file chunking, live audio/video integration,
  chain-gated key release, ticket consumption or connection to funded journals.
  Existing vaults, native transactions and saved pilot records are unchanged.

Next integration work is an authenticated transport adapter and independently
operated endpoints, including device keystores, recovery/rotation and metadata
review. Keep that evidence separate from this one-host file exchange.
