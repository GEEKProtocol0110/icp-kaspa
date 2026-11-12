# A message for one recipient: local encryption lab

[Plain-English introduction](PLAIN-ENGLISH.md) · [Documentation](README.md)

This experiment encrypts a fictional message for one pinned recipient delivery
key. The recipient checks the sender and message integrity before recording a
signed acknowledgment. It uses real cryptographic operations on one local host.
It performs **no network delivery, Kaspa transaction or chain-gated key release**.

The later [file/bytes adapter](RECIPIENT-FILE-ADAPTER.md) exposes the same
cryptographic flow to separate role processes, with endpoint-owned test-key files,
authenticated policy pins and a ciphertext-only loopback HTTP handoff. It retains
this namespace and limits; one-host processes do not establish device isolation.

The new `icp-recipient-lab-v0` namespace is separate from the old transfer lab,
the simulated release ledger and the proposed R0 service. No existing signature,
anchor or model grant becomes permission to release a real key.

## Try the fictional exchange

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/recipient_lab.py
python3 -m unittest discover -s tests -p 'test_recipient_lab.py' -v
```

The demo uses fictional offices, freshly generated in-memory keys and temporary
databases. It checks that the intended recipient decrypts the message, an
unrelated key fails, and the recipient's receipt verifies. It prints public
policy, ciphertext, certificate and receipt with the label
`LOCAL_ONLY_RECIPIENT_ENCRYPTION_NO_CHAIN`. It does not print private keys,
plaintext or a raw content key. No real agency or official is involved.

The [saved transcript](../evidence/recipient-lab-demo.json) contains one random
synthetic run. Its successful plaintext comparison is a local demo result,
not public proof of decryption. The transcript's public signatures can be
verified without obtaining a private key.

## Cryptographic choice and scope

The existing pinned dependency, `cryptography==50.0.2`, implements the HPKE
single-shot API. This experiment selects HPKE base mode with
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. The library performs
encapsulation, key derivation and encryption; the application does not implement
those constructions or export a raw symmetric key. Every encryption call uses
fresh ephemeral material, including repeated plaintext and record labels.

HPKE base mode supplies recipient encryption, not a sender identity. Separate
Ed25519 signatures bind approval and sending to the complete encrypted-message
manifest. Identity and delivery keys have different purposes; all four public
keys must differ. Low-order X25519 delivery keys are rejected through library
validation before enrollment.

This is an application experiment built from an established construction. It
has **not received independent cryptographic review** and does not freeze a
production/R0 suite. It demonstrates no post-quantum protection. The available
library's other algorithms are not silently negotiated or used as fallbacks.

Primary references: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html),
[the pinned HPKE API](https://cryptography.io/en/50.0.2/hazmat/primitives/hpke/)
and [Ed25519](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/).

## Binding an identity to its delivery key

The trusted operator pins an approver, sender, recipient identity and a distinct
recipient delivery public key in `DeliveryPolicy`. This configuration establishes
which keys are trusted; the lab does not discover a person's legal identity,
verify government employment or provide a certificate authority.

1. A local registry generates a random, 60-second challenge and encrypts a
   fresh secret token to the pinned delivery key. Its context binds the complete
   policy, namespace and challenge ID. Only the expected token hash is stored;
   it is not published in the challenge.
2. The recipient decrypts the token and signs its context-bound hash with the
   separate recipient identity key. Substituting either key or challenge fails.
3. The trusted approver verifies the response against the saved challenge and
   commits one certificate plus the consumed challenge in one SQLite transaction.
   Concurrent registration attempts resolve to one certificate. Restart preserves
   the used challenge; an altered policy or database role fails without reset.

`get_binding()` recovers the saved public certificate after a lost return or
restart, without repeating enrollment or creating a second certificate.

The certificate is an approver attestation that this local possession check
passed. It is not an independently verifiable proof of secure hardware, exclusive
human control or real-world identity. A compromised approver can issue a false
certificate. Enrollment permits at most 16 total challenges per pinned database;
there is no automatic cleanup, key rotation, revocation or re-enrollment service.

## Message and receipt rules

| Object | Bound context |
| --- | --- |
| Policy | Version, local-only mode, TN10 namespace, exact suite, authority/delivery keys, delivery epoch and size/lifetime limits |
| Binding certificate | Policy, recipient/delivery key/epoch, challenge and proof hashes, registration time and approver signature |
| Message encryption | Policy, random transfer ID, record ID/version, identities, delivery key/epoch, certificate digest, issue/expiry times and plaintext length |
| Message approval and sender signature | Complete encryption context plus ciphertext SHA-256 |
| Recipient receipt | Complete signed-envelope digest, transfer/policy/recipient/epoch, claimed acceptance time and local-only status |

HPKE `info` is a purpose-specific domain plus the canonical complete encryption
context. The later ciphertext hash is excluded from that context to avoid a
self-reference; the outer signatures bind it. Re-signing altered record metadata
or substituting another valid certificate cannot repair the original encryption
context. The receiver verifies the binding and both message signatures before
attempting decryption.

All digests/signatures use separate `icp/recipient-lab/v0/` purposes. Digest
inputs are the purpose, a zero byte and canonical JSON. Signatures cover the
purpose, a zero byte and the raw 32-byte digest. JSON uses sorted keys, compact
ASCII encoding and no non-finite values. Strict field sets, fixed lowercase hex,
unsigned integers below 2^53 and duplicate-key rejection apply. The maximum
plaintext is 64 KiB; maximum lifetime is one hour (default five minutes).
The fixed suite adds 48 ciphertext bytes. Wire input is bounded to twice 64 KiB
plus 8,192 bytes. This experimental JSON format is not an adopted Internet or
Kaspa wire protocol.

The receiver stores only a receipt under a unique transfer ID, committing it
before returning plaintext. Two connections to one intact database cannot both
accept that ID. The database pins policy and role and uses `synchronous=FULL`.
A crash after commit can lose the plaintext return; `get_receipt()` recovers
the signed claim, not plaintext. Recovery does not automatically redeliver it.
An independent, copied or restored database can accept again. These are local
replay checks, not global grant accounting or exactly-once network delivery.

## What this does not protect

The sender and encryption process already know the plaintext. Anyone holding
the recipient's delivery private key can decrypt a recorded ciphertext outside
the receiver API. Later compromise of that static key exposes earlier messages;
this experiment supplies no forward secrecy against recipient-key compromise.
Expiry is an API check against caller-supplied trusted time. It cannot make a
delivered ciphertext expire, erase a key or prevent screenshots, copying or
later disclosure. No independent timestamp or rollback-resistant clock is used.

A receipt authenticates the recipient identity key's claim. That key holder
can sign a matching receipt without decrypting. It is not proof of reading,
factual truth, secure deletion or behavior by a particular person.

Keys and plaintext occupy ordinary process memory on one host. No protected
key store, secure erasure or device isolation is established. Public envelope
metadata exposes key linkage, record labels, timing and message length. It is
not suitable for publishing real sensitive exchanges. Real transport,
metadata protection, recipient directories, rotation, hardware custody and
institutional integration need separate design and review.

The [release draft](READ-TICKET-RELEASE-DRAFT.md) still requires service-owned
content-key handling, wire/delivery review, native ticket/refund rules,
authoritative grant accounting, writer fencing and recovery before remote
release. This lab directly encrypts a message to a recipient; it does not wire
those gates into the [simulated ledger](RELEASE-LEDGER-MODEL.md). Current vaults,
funded sessions and live anchor rules are unchanged.

The [release-service design](RELEASE-SERVICE-DESIGN.md) now specifies proposed
ownership and cross-store recovery boundaries. The next coordinator model keeps
fake vault responses separate from this lab's real encryption operations.

See [verification](../evidence/recipient-lab-verification.md) for adversarial
coverage and test counts.
