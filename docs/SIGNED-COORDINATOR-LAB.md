# Signed permissions and recipient requests: local lab

[Plain-English introduction](PLAIN-ENGLISH.md) · [Recovery model](RELEASE-COORDINATOR-MODEL.md) · [Service design](RELEASE-SERVICE-DESIGN.md)

**Conventional signatures over synthetic release decisions.** This lab adds
signed admission, recipient challenges and grant revocation to the separate-store
recovery model. Responses remain non-secret placeholders. It has no content
keys, encryption, native tickets, RPC, transport or remote endpoint. Its encoding
is an experimental lab format, **not an adopted or reviewed R0 wire protocol**.

A separate [bound response lab](BOUND-RESPONSE-LAB.md) now adds a real
cryptographic delivery-key possession check and durable signed response records
to these boundaries. This document describes the original signed lab; its
model binding label remains a fixture unless that separate layer is used.

## In plain English

Two separate signing roles approve the exact permission. The recipient then
signs a fresh service challenge before that permission can be reserved. After a
placeholder delivery has been saved, the recipient signs another fresh challenge
naming its exact digest. A separate revocation signer can block further delivery.

A restart keeps the saved permission, budget charge and delivery. It invalidates
outstanding challenges from the previous service generation. Retrying delivery
uses a new challenge and returns the same saved bytes. A copied signed request
can be relayed once by its holder; signatures alone do not secure a connection.

## Implemented boundary

[scripts/signed_coordinator_lab.py](../scripts/signed_coordinator_lab.py)
provides `SignedCoordinator`, extending the existing coordinator's checkpointed
ledger, private fake-vault outbox and delivery journal. The base module now
shares protected transaction helpers so evidence and permanent claims are saved
together. Its original unsigned harness API remains available in the separate
base experiment; it is not an authentication fallback in `SignedCoordinator`.

The signed policy pins five **distinct Ed25519 public keys**: approver, sender,
recipient identity, revoker and service challenge signer. It also pins service,
budget, recipient/binding labels, accounting limits and challenge bounds. Every
component and the independent authority pin the resulting policy digest.
Opening the stores with different keys or limits fails; key migration is not
implemented. Private signing keys in the demo/tests are ephemeral memory values.
They are not wallet or content-encryption keys and are not published in evidence.

| Operation | Signature and durable requirement |
| --- | --- |
| Permission | Approver and sender separately sign the complete context and pinned recipient identity |
| Reservation challenge | Service signs a fresh random nonce bound to permission, request, recipient/binding, epochs, deployment identity, current generation and deadline; save/checkpoint before returning it |
| Admission | Recipient signs that exact reservation challenge; permission/request digests, original evidence, accepted time, used nonce, claims and quota charge share one ledger event |
| Preparation / commit | Revalidate stored signed admission on every journal boundary; existing current-policy, revocation, original-deadline and fake-observation gates remain |
| Retrieval challenge | Service additionally binds the original admission digest and complete committed-response digest; the client checks the intended permission and expected response digest before signing |
| Dispatch | Recipient signs the exact retrieval challenge; signature evidence, accepted time and used nonce share one delivery event before placeholder bytes return |
| Revocation | Separate revoker signs exact grant/permission, next global sequence, fresh revocation ID and short validity interval; record it atomically with the permanent revocation |

The response context now includes both the complete permission digest and the
actual original signed admission-request digest. This avoids trying to put a
future signature's digest into its own approval. The approved `Context.request`
and `Context.challenge` remain signed synthetic intent labels; neither is the
fresh server nonce. The response operation stays `(service, budget, grant)`.
A different valid permission for an already claimed operation causes an
integrity halt; writer/epoch changes cannot create a replacement operation.

The same signed reservation request is not a retry token: it is permanently
consumed with its admission. After a lost acknowledgment, recovery verifies the
saved grant and the trusted local administration interface reconciles it.
Retrieval retries use fresh signed challenges and preserve identical response
bytes. Status remains a trusted local administration read, not a protected
network status endpoint, and exposes neither candidate bytes nor signed evidence.

## Lab encoding

Namespace: `icp-signed-coordinator-lab-v0`.
Mode: `LOCAL_SIGNED_COORDINATOR_SYNTHETIC_RESPONSES_NO_CHAIN`.
Network marker: `testnet-10-simulation`. The core placeholder keeps its original
`SYNTHETIC_COORDINATOR_NO_KEYS_NO_CHAIN` marker; no real delivery suite is implied.

All wire entry points require nonempty canonical JSON **bytes**, at most 32 KiB.
Encoding uses sorted keys, compact separators and ASCII-escaped strings.
Duplicate keys, extra/missing fields, trailing whitespace, non-finite numbers,
malformed/uppercase hex and ambiguous numeric types are rejected. Integers are
exact non-boolean values in `[0, 2^53)`; fixture times are logical seconds, not
current-chain time or an adopted production timestamp specification.

All messages carry exact version/mode/network/policy/service/budget headers.
Permission contexts contain exactly the base model's `Context` fields. The
permission envelope contains `body`, `approval` and `sender_signature`.
Challenges contain a `body` and service `signature`; answers contain that exact
`challenge` envelope and the recipient `signature`. Revocation contains `body`
and revoker `signature`. Strict schemas are implemented alongside each verifier.

Signatures use the library's Ed25519 implementation over:

`ASCII("icp/signed-coordinator-lab/v0/" + purpose) || 0x00 || canonical(body)`.

Signature purposes are `approve`, `send`, `challenge/reserve`, `request/reserve`,
`challenge/retrieve`, `request/retrieve` and `revocation`. Recipient signatures
cover the complete signed challenge envelope. SHA-256 identifiers use the same
prefix/zero/canonical encoding with separate `policy`, `permission` and
`admission-request` purposes. Base journal/context hashing keeps its own namespace.
Signatures from the earlier transfer, recipient or release-ledger experiments
are not accepted as these lab authorizations.

Default challenge lifetime is 30 logical seconds, configurable up to 60 and
clipped to the original grant/window deadline. Outstanding challenges require
the exact current authority identity and generation. Admission proof expiry
is checked at admission, then retained as historical evidence; it does not
shorten the original grant to 30 seconds or extend its lifetime. Retrieval
requires another current proof. At most 16 challenges per grant/purpose are
issued by default, configurable up to 64, including expired or lost ones.
Exhaustion stops progress; garbage collection/reset is not implemented.

Revocation sequences are exact-next and global to this ledger; IDs cannot be
reused across grants. Repeating the exact accepted revocation is reconciliation
even after its certificate deadline. Changed retries or stale/gapped sequences
fail. Revocations remain effective after restart and do not refund quota, erase
responses or clear used/possible-disclosure flags. Only grant-scoped revocation
is implemented here; broader record/registry/policy scopes remain design work.

## Run and verify

From the repository root:

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/signed_coordinator_lab.py
python3 -m unittest discover -s tests -p 'test_signed_coordinator_lab.py' -v
```

The demo prints public signed fixture evidence, sanitized status, identical-retry
results and zero content-key/RPC/broadcast counts. Public signing keys,
signatures, labels, sizes and times are metadata. No record plaintext, private
signing key or placeholder body is printed. Random keys/nonces change the
transcript between runs. See [the example](../evidence/signed-coordinator-demo.json)
and [verification record](../evidence/signed-coordinator-verification.md).

## Remaining assumptions and limits

The pinned recipient key is a configured signing identity, not proof of a
real person's identity or legitimate human intent. The delivery-binding label
is still a trusted fixture. This does not integrate the HPKE lab's encrypted
possession check or prove possession of a delivery/decryption key. Record IDs,
cipher hashes/sizes, ticket/consume labels and two boolean chain observations
are synthetic inputs; signatures do not verify their factual truth.

The service signing key, code, clock, authority and stores still share a trusted
host. Python private members and transaction helpers provide no isolation from
privileged code. Observation injection, epoch changes, recovery administration
and status reads remain trusted local harness operations. There is no HSM,
secure transport/channel binding, protected signing endpoint, production fencing
provider, admin quorum, real record-ingestion validation or response attestation.
Do not expose this class directly as a network API or connect content keys.
Challenge exhaustion and snapshot journals have unresolved availability/resource
limits; these tests are not a capacity benchmark or deployment hardening.

A test relays a captured signed retrieval without the recipient's private key:
the first caller gets the placeholder and consumes its nonce. The intended
recipient needs a new challenge to retry. Later recipient-only encrypted
responses and an authenticated transport require separate design and review.
A test also restores the authority with all stores and loses an accepted signed
revocation. Cryptography cannot reconstruct a trusted witness's erased history.
Component-only rollback detection and generation fencing depend on that
independent authority retaining its history, as in the base model.

The existing final-check-to-arrival race remains: revocation or reorg after
accepted dispatch cannot recall bytes. A person who eventually learns real
plaintext/key material can copy it. No consensus proof, factual-truth proof,
quantum safety, audit completion or mainnet/production readiness is established.

Next: review these signed boundaries and the separate
[bound response experiment](BOUND-RESPONSE-LAB.md). Native ticket/consume/refund
bindings, protected real-key storage/delivery, independent enforcement and
authenticated transport remain separate acceptance milestones.
