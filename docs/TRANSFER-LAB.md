# Local send/receive verification experiment

Status: local research code, version `icp-transfer-lab-v0`. This additive module
is separate from the vault/watchtower. It has no RPC, funding, transaction
submission, chain-anchor verifier, STARK program or custody-key access.

The separate [transfer anchor observer](TRANSFER-ANCHOR.md) now supplies a
read-only commitment tracker for trusted-node scan responses. Its current
evidence is synthetic; it changes neither this module's receiver acceptance
nor the out-of-band key-delivery assumption.

The experiment turns the before-send/after-receive idea into a bounded exchange:
an explicit policy approver authorizes a ciphertext-bound manifest, the sender
signs that same exchange, and the recipient decrypts/authenticates it before
committing a receipt to a local replay database. This is an experimental
off-chain component, not the paper's complete data-release protocol.

## Run it

Use Python 3.11+ and the pinned lab dependencies:

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/transfer_lab.py
python3 -m unittest discover -s tests -p 'test_transfer_lab.py' -v
```

The demo generates three fresh in-memory Ed25519 role keys and a synthetic
payload, then uses a temporary replay database. It prints public policy,
ciphertext, signed manifest and receipt, with explicit `LOCAL_ONLY_NO_CHAIN_ANCHOR`
and `VERIFIED_LOCAL` labels. The AES key, private role keys and plaintext are
not printed or persisted. The process holds them in ordinary memory; no
zeroization, enclave, endpoint isolation or production handling is established.
The demo exits unsuccessfully if its integrated verification checks fail.

Use synthetic data only. Full repository CI installs these dependencies and
runs the experiment alongside the custody/controller tests. The lab's three
keys are distinct logical roles on one host, not demonstrated host separation.

## Policy and signed exchange

The pinned policy includes approver, sender and recipient public keys, a
plaintext limit of at most 1 MiB, and a permission lifetime of at most one hour
(default five minutes). All three role keys must differ. This lab's policy
uses a `testnet-10` namespace and `offchain-local` mode; those labels are not
evidence of a node check, accepted transaction or chain confirmation.

| Object | Bound fields |
| --- | --- |
| Policy identifier | Version, network, local mode, all role keys, size and lifetime limits |
| Manifest identifier | Version, network, policy ID, random transfer ID, sender/recipient keys, issue/expiry times, nonce and ciphertext SHA-256 |
| Approver signature | Manifest ID under the approval-specific signature domain |
| Sender signature | Same manifest ID under a different send-specific domain |
| Recipient receipt | Manifest ID, transfer ID, policy/network/version, ciphertext hash, recipient, claimed acceptance time and `VERIFIED_LOCAL` status |

Policy/manifest/body digests use SHA-256 with separate domain prefixes, a zero
byte separator and canonical JSON: sorted keys, no optional whitespace, ASCII
encoding, lowercase fixed-size hex and bounded unsigned integers below 2^53.
The fixed schema permits only the specified scalar fields. Unknown fields,
duplicate JSON keys and oversized input bytes are rejected. Wire size is
bounded at twice 1 MiB plus 8,192 bytes for the hex ciphertext and metadata.

Signature messages are a role-specific domain, a zero separator and the raw
32-byte identifier. The exact domains and field names are in
[transfer_lab.py](../scripts/transfer_lab.py). This is a versioned experimental
encoding, not a claim of interoperability with Kaspa transaction signatures.

## Encryption and acceptance

`seal` generates a fresh AES-256-GCM key and 12-byte random nonce per message.
Authenticated associated data is the complete manifest context before the
ciphertext hash is added. This avoids a circular hash/encryption dependency.
The later manifest signatures bind both that context and the ciphertext hash.
Changing metadata even with new valid signatures fails decryption unless the
payload was encrypted with matching associated data.

`approve` requires the pinned approver key. `sign_send` verifies that approval,
checks the local permission window and requires the distinct pinned sender.
These functions authenticate role-key
possession; they do not infer human intent or independently review content.
The policy approver and the process selecting the policy are trusted.

The receiver checks schema, limits, ciphertext commitment, policy, both role
signatures and the local-clock interval `issued_at <= now < expires_at`. It
then authenticates/decrypts with the separately supplied 32-byte AES key. Key
distribution is **not implemented**: the demo passes the secret in memory as
an explicit trusted out-of-band assumption. There is no key-encapsulation or
authenticated remote delivery protocol.

Anyone who already holds the AES key can decrypt outside this API without
checking approval or expiry. A test demonstrates that boundary. Enforcing
policy at the key-delivery/release service is therefore a separate essential
integration step, not a property established by recipient fields in a manifest.

After successful decryption, the receiver signs a receipt and inserts it under
a unique transfer ID before returning plaintext. Two connections sharing the
same intact SQLite database cannot both accept the same ID. The database pins
the complete policy ID; changing policy fails rather than discard old history.
It stores receipts, not plaintext, ciphertext or AES/private signing keys.

Replay protection is local to that database. A fresh, restored or independent
database can accept the same transfer again. It is not an on-chain consumed
read ticket, global record-release counter or cross-host exactly-once guarantee.
A crash after commit but before return can lose delivery; `get_receipt` recovers
the stored acknowledgment, not plaintext. Applications must explicitly reconcile
such outcomes rather than silently recreate the DB or redeliver data.

## Receipt semantics

`verify_receipt` checks the exchange signatures, exact receipt binding and
recipient signature. Historical verification uses the receipt's signed
`accepted_at` claim to check the permission interval; it does not consult a
trusted timestamp service or establish when the signer actually acted.

The receipt proves that the pinned recipient key signed a matching claim.
A holder of that key can sign a receipt without decrypting anything. An
explicit test demonstrates this limitation. There is no remote-execution
proof, proof of factual truth, proof of secure deletion or assurance that an
authorized recipient will keep the plaintext private. Once disclosed, a later
chain reorganization cannot reverse disclosure.

Conventional Ed25519 signatures do not establish post-quantum authentication.
The use of AES-256 does not make the complete protocol quantum-resistant.
All-key compromise, malicious endpoints, protected key delivery, metadata
privacy and stronger authorization require further specification and review.

## Inspectable transcript and adversarial checks

[transfer-lab-demo.json](../evidence/transfer-lab-demo.json) is one public
synthetic transcript. It includes enough public material to verify signatures
and binding, but no decryption/private signing keys. Its reported plaintext
match comes from the local demo, not a public proof of decryption. A test checks
this fixed transcript without regenerating its keys or signatures.

The 29 lab tests exercise integrated encryption and receipt verification;
fresh keys/nonces/IDs; ciphertext/hash/tag tampering; signed-metadata changes;
associated-data binding despite re-signing; wrong roles/keys; role-signature
separation; time/size bounds; namespace/policy pinning; restart and concurrent
replay; independent-DB replay scope; policy-change refusal; strict JSON/hex;
receipt transplant/signature/status changes; recipient-attestation limits;
historical receipt checks; JSON whitespace and policy validation.

## Kaspa integration gate

Before connecting this to the paper's data-access design, specify a consumed
read-ticket/outpoint and policy commitment, accepted-chain validation and
confirmation/reorg policy, persistent release accounting, proof public inputs,
recipient-specific key delivery and confidentiality review. A future anchor
must authenticate the exact exchange and authority rather than merely record
an arbitrary hash. No placeholder chain confirmation is emitted by this lab.

Primary library references: [AEAD](https://cryptography.io/en/50.0.0/hazmat/primitives/aead/)
and [Ed25519](https://cryptography.io/en/50.0.0/hazmat/primitives/asymmetric/ed25519/).
See [SECURITY-TARGET.md](SECURITY-TARGET.md) for the separate custody target.
