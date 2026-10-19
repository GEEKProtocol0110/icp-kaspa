# Delivery-key verification and signed response records

[Plain-English introduction](PLAIN-ENGLISH.md) · [Signed requests](SIGNED-COORDINATOR-LAB.md) · [Service design](RELEASE-SERVICE-DESIGN.md)

**Local lab with real enrollment cryptography and non-secret response bundles.**
HPKE encrypts a random registration challenge to a pinned X25519 key. It does
not encrypt a record, content key or response. The service signs a durable
record describing each exact dummy response. There is no native ticket, RPC,
transport endpoint or adopted R0 wire/delivery suite.

## What changed

The earlier signed coordinator authenticated a recipient signing key while its
delivery-key label remained a fixture. This separate lab commits an actual
X25519 public key and epoch into that label. Admission and delivery require a
registered binding, backed by a fresh encrypted challenge, recipient identity
signature, distinct approver signature and service registration certificate.

The service also saves a signed response record inside the private vault
candidate. Committing the response copies that exact record into the ledger.
Retries return the same response, context, registration and signature bundle.
A restart cannot silently sign a replacement for an existing candidate.

| Component | Added durable state |
| --- | --- |
| Policy | Delivery label commits to service, budget, recipient identity, X25519 public key, key epoch and enrollment suite |
| Ledger | Encrypted enrollment challenge, private expected-token hash, used nonce and complete accepted binding evidence; exact response record at commit |
| Private fake vault | One non-secret candidate plus its complete signed response record, in the same checkpointed event |
| Delivery journal | Existing recipient request evidence and permanently used retrieval nonce |
| Independent authority | Existing generation fencing, clock continuity and checkpoints covering the added state |

[scripts/bound_response_lab.py](../scripts/bound_response_lab.py) extends the
signed coordinator. Shared protected candidate/commit helpers preserve the
base model's behavior while allowing the record to share its response's save.
All components remain trusted software on one host, rather than isolated services.

## Prove the encryption-key binding before admission

1. Configure five distinct Ed25519 roles, as in the signed lab, plus a separate
   X25519 delivery public key. Low-order delivery keys and public-byte reuse
   across encryption/signing roles are rejected. Demo keys are generated
   independently; checking public keys cannot prove private-key separation.
2. Derive the binding label from those exact delivery attributes and pin it in
   `SignedPolicy`. `DeliveryConfig` checks that commitment. Changing key,
   identity, service, budget or key epoch changes the pin and policy identity.
   Existing stores cannot reopen under a changed configuration.
3. Save and independently acknowledge a service-signed enrollment challenge.
   A fresh random 32-byte token is HPKE-encrypted to the configured X25519 key.
   Service/budget/policy/configuration, recipient/key/epoch/suite, authority,
   generation, nonce and deadline are authenticated context. Only the expected
   domain-separated token hash is retained privately; the raw token is not saved.
4. The recipient helper verifies the challenge and configured keys, decrypts
   with the delivery private key, and signs the context-bound token hash with
   its separate identity key. The approver signs that exact proof/challenge link.
5. Registration checks both signatures, the issued nonce, current generation
   and epoch, deadline and private expected hash. One ledger event consumes the
   nonce and saves a service-signed certificate with the approval, identity proof
   and original challenge. Its checkpoint precedes certificate return.
6. Permission admission, preparation, commit and dispatch require that saved
   binding and the configured current delivery epoch. The original signed
   permission and recipient-request checks still apply.

A signature made only with the identity key cannot answer the encrypted token.
The expected hash is absent from the public challenge before a proof is made.
After successful registration, the signed proof contains the token hash and the
nonce is permanently used. The certificate is the service's attestation that
it checked the proof, not a zero-knowledge proof or an independent public proof
that a particular person exclusively controls the private key.

There is one binding per configuration. `get_binding` returns only its saved
public registration evidence, after checkpoint verification. Lost replies
recover those exact bytes. A completed binding remains historical evidence
after its short enrollment challenge expires. Outstanding challenges require
the current generation and cannot survive a restart as new authorization.
Enrollment issuance is bounded by the signed policy's challenge limit (16 by
default). Exhausted/lost challenges are not automatically reset.

## Save the response record before returning a bundle

The service signs a new `response-record` body while preparing the private
candidate. It binds the exact raw-placeholder digest, full approved-context
hash, actual permission/admission digests, complete registration hash, delivery
public key/suite/epoch, original policy epoch/deadline, stable operation,
preparation time/generation, authority identity and authorizing ledger checkpoint.
The operation stays `(service, budget, grant)`; generation is an attribute.

The candidate and signature are one vault event. They must be independently
acknowledged before commit. The ledger then saves the exact response and exact
record in its own event, with permanent used/possible-disclosure flags and no
additional charge. Missing or conflicting signatures, registration claims or
vault/ledger records halt recovery; they do not trigger a replacement signature.

The fresh signed retrieval challenge continues to name the **raw placeholder
digest**, not the whole bundle digest. Dispatch checks current gates and consumes
the signed nonce before returning a canonical bundle with `response`, `context`,
`binding` and `record`. Those saved values have no per-retry timestamp/nonce, so
bundle bytes remain identical across fresh retrieval requests and restarts.
Pending response bytes and signatures are absent from status and binding reads.

`verify_response` checks the recipient's intended dual-signed permission,
original signed admission, exact bundle context, response digest, registration
signature chain and service response signature. It also checks deployment and
historical generation relationships. The opaque ledger checkpoint is a signed
service claim; the client does not independently verify the authority database
or Kaspa consensus. The caller must supply the intended permission/admission.

Verification is historical: a previously valid signature remains verifiable
after expiry or revocation. It grants no new delivery permission. The server
still rejects new requests after accepted revocation, inactive epochs, stale or
disagreeing fake observations, or original grant/window expiry.

## Encoding and reproduction

New attachment/enrollment namespace: `icp-bound-response-lab-v0`.
Mode: `LOCAL_DELIVERY_BINDING_ATTESTATION_SYNTHETIC_NO_CHAIN`.
Domain prefix: `icp/bound-response-lab/v0/`.
Network marker: `testnet-10-simulation`.

HPKE uses the pinned library's base mode with X25519, HKDF-SHA256 and AES-256-GCM.
Its only plaintext here is the random enrollment token. HPKE context uses the
new domain plus the canonical challenge fields excluding the ciphertext.
Ed25519 signs the new domain, purpose, zero separator and canonical object.
Purposes distinguish `binding-challenge`, `binding-proof`, `binding-approval`,
`binding-certificate` and `response-record`. Identifiers have separate purposes.

The inner permissions/retrieval requests retain the signed lab's exact format,
now under the key-committing policy. Earlier recipient-lab binding proofs are
not accepted. All public byte inputs inherit bounded, strict canonical JSON
parsing (32 KiB), exact fields/types and lowercase hex checks. Signed/context
objects must match canonical bytes; boolean/float values cannot compare as
integer epochs or limits. Times are
logical fixture seconds, not a production wall-clock guarantee. No R0 encoding,
production cipher suite or migration policy is adopted by this experiment.

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/bound_response_lab.py
python3 -m unittest discover -s tests -p 'test_bound_response_lab.py' -v
```

The [public demo](../evidence/bound-response-demo.json) contains full public
configuration, permission/admission, registration and the **committed synthetic
bundle**. Its random placeholder is explicitly non-secret. It contains no raw
enrollment token, private signing/decryption key, content key or real record.
Public keys, ciphertext, proof hashes, labels, sizes and times remain metadata.
A verifier needs only those public objects. Random keys/nonces change the demo.
See [the verification record](../evidence/bound-response-verification.md).

## Limits and next gate

This establishes a checked key-possession event at enrollment, not a person's
real identity, exclusive ownership or continued key availability. A compromised
service or private expected-hash store undermines that check. The certificate
and response record attest trusted service decisions; they do not establish
factual truth, decryption, byte arrival, execution or consensus acceptance.

The response bundle is deliberately **unencrypted**. A test relays a copied
signed retrieval without either recipient private key and receives the dummy
bundle once. Real recipient-only responses, authenticated transport and channel
binding need separate implementation and review. A completed key-possession
check alone does not protect data sent in cleartext.

Record/ciphertext sizes and native ticket/consume fields remain fixtures; two
boolean chain observations remain trusted synthetic inputs. Status, recovery
administration, epoch changes and observation injection remain local harness
operations. There is no mainnet mode, key export, content-key connection,
network server, hardware isolation, independent storage provider or live ticket.
Changing epoch blocks existing operations; automatic key/certificate rotation,
multiple-recipient directories and broader registry revocation are unimplemented.

Independent authority history is still trusted. Restoring it with every store
can erase accepted revocations/claims; signatures cannot reconstruct that lost
history. Final-check-to-arrival races and recipient copying remain. No quantum
safety, independent audit or production readiness is demonstrated.

Next: review these attachment/registration formats and specify native ticket,
consume/refund bindings before connecting real content keys. Protected key
storage/delivery, independently enforced continuity and authenticated transport
remain separate acceptance milestones.
