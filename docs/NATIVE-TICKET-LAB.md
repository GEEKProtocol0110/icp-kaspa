# Offline native ticket lab

[Project home](../README.md) · [Documentation](README.md) · [Native design](NATIVE-TICKET-DESIGN.md)

**Working native transaction code, using fabricated inputs and public fixture
keys.** It builds and signs issuance, consumption and refund examples and
verifies them in Kaspa's native script engine. No transaction is submitted.

Run from the repository root with the pinned Rust toolchain:

```bash
cargo run --locked --example native_ticket_lab
cargo test --locked --features live native_ticket_lab
```

The example accepts no arguments, secret files, wallet configuration or RPC
endpoint. It prints public plans, native transaction IDs/hashes, commitments,
output amounts/scripts and VM results. It omits signed transaction bytes.
The source outpoint is fabricated; all role keys are intentionally known.
Never fund fixture addresses. There is no connection to the release models.

## What works

| Action | Native fixture transaction |
| --- | --- |
| Issue | Spend one fabricated 24,000,000-sompi funding input; create a 12,000,000 ticket and 10,000,000 funding change; fee 2,000,000 |
| Consume | Spend that issue transaction's actual calculated output 0; return 10,000,000 to the pinned return key; fee 2,000,000 |
| Refund | Alternative spend of the same fabricated ticket, with a distinct commitment and ID; same return/fee |

Funding, ticket and return keys are distinct native Schnorr fixture keys. The
builder fixes version 1, native subnetwork, zero gas/sequence/locktime, input
compute budget 100, exact output order/scripts and absent covenant bindings.
Funding bounds are 24,000,000–100,000,000 sompi. It checks the complete fabricated
UTXO entry, commits calculated storage mass, signs only `SIG_HASH_ALL`, then
checks the exact layout and native VM result.

The lab can sign **both alternative terminal examples** because it has no
durable branch controller. They conflict on the same outpoint. This is useful
transaction evidence, not enforcement of the proposal's one-branch rule.
Refund's closure/approval digests and consumption's admission digest are
invented inputs. No real signatures, permission, revocation, quota, clock,
unused-ticket history or node observations are validated by these placeholders.

## Lab encoding and integrity

The separate namespace is `icp-native-ticket-lab-v0`, mode
`OFFLINE_NATIVE_FIXTURES_NO_CHAIN_NO_AUTHORIZATION`. It tests the proposed N0
native **layout** without adopting N0/R0 authorization or wire formats.
Payload prefixes end in `TN10-LAB0` followed by NUL, rather than N0's prefix.
Append the raw SHA-256 digest of the purpose-separated canonical lab plan:

`ASCII("icp/native-ticket-lab/v0/" + action) || 0x00 || canonical_plan`

The plan is sorted compact ASCII JSON, at most 16,384 bytes. Its closed Rust
schemas are in [native_ticket_lab.rs](../src/native_ticket_lab.rs). Unknown and
duplicate fields, alternate encodings, floats, boolean numeric substitutions,
non-ASCII strings and integers above `2^53-1` fail. Optional fields are explicit
nulls. Keys and fabricated funding outpoint must equal the known fixtures;
identities use bounded `model:` labels and digest strings use lowercase hex.

The issue plan has no issuance/admission/closure fields populated. Terminal
plans pin the exact independently reconstructed issue ID/output/value/script.
Consume requires admission/window evidence and forbids closure; refund requires
closure evidence and forbids admission. These shape checks do not authenticate
the evidence or establish prior service history.

`check_prepared` checks exact layout, recomputed storage mass, compute budget,
minimal signature encoding, hash mode and VM validity. `check_saved` additionally
compares the full native transaction hash with a trusted previously saved hash.
It detects a different valid signature on the same transaction body. Neither
function supplies persistence, an authenticated checkpoint or writer fencing.

The native tests demonstrate that V1 compute-budget and storage-mass changes
preserve both transaction ID and signature hash, while the full native hash
changes. The native script engine still accepts those tested changes; layout
checks reject them. A damaged signature fails; a different valid signature
retains the ID but fails comparison against the original saved native hash.
An alternate valid sighash and an arbitrary controller-signed destination can
pass ordinary P2PK verification while failing the ticket checks.

## Evidence and next boundary

[Public fixture vectors](../evidence/native-ticket-lab-demo.json) contain all
three plans, commitments and native summaries. A Rust test reproduces those
fixed vectors; Python's standard-library SHA-256 independently checked their
canonical commitment calculations. They contain no signed outbox or private key.
Read the [verification record](../evidence/native-ticket-lab-verification.md).

Twenty-eight native tests cover valid linked layouts, strict parsing, source/
key/value limits, exact issue binding, field/signature mutations and the P2PK
policy counterexamples. Existing custody behavior is unchanged.

VM success does not establish UTXO existence, live acceptance, mass/fee relay
policy, confirmation confidence or real permission. Deterministic known test
keys and nonce inputs are for reproducible vectors, never production material.
The next milestone is a separate durable fixture controller that serializes
branch choice and recovers the same saved transaction through crashes. Native
observation, independent signer enforcement, reviewed authorization/wire,
real-key custody and remote delivery remain later gates.
