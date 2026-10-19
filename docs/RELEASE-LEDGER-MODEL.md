# Synthetic release-ledger model

[Plain-English introduction](PLAIN-ENGLISH.md) · [Documentation](README.md)

In everyday terms, this tests a service's saved record of **who claimed a
permission and how much of a release limit they used**. It checks duplicate
requests, crashes and changes to chain observations. It returns a clearly
labeled example in place of a decryption key. Copying the database can defeat
its accounting; global safeguards remain future work.

This implements the local state/accounting experiment proposed in the
[read-ticket draft](READ-TICKET-RELEASE-DRAFT.md). It is **not a key-release
service**. It creates no content keys, recipient encryption, service attestation,
Kaspa transaction, RPC connection or funded ticket. The only response is a
publicly labeled `NON_SECRET_RESPONSE_PLACEHOLDER`.

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 scripts/release_ledger_model.py
python3 -m unittest discover -s tests -p 'test_release_ledger_model.py' -v
```

The runnable demo uses disposable Ed25519 identities, a temporary database and
a simulated clock. It prints public context and a placeholder, never private
keys. The saved [example](../evidence/release-ledger-model-demo.json) is one
synthetic run; randomly generated identities/nonces make later runs differ.

## Implemented boundary

| Object or action | Model behavior |
| --- | --- |
| Policy | Pins service, stable budget ID, epoch, authority keys, clock/window/quota and observation limits to the database |
| Record | Immutable public record/version/ciphertext metadata; unique fake key tag across versions |
| Issuance | Separate approver/sender model signatures; permanent grant/ticket reservation and fake issuance outbox before confirmation |
| Request | Recipient-signed fresh challenge binds purpose, policy, service, network, grant, ticket, delivery tag and epoch |
| Reservation | One immediate SQLite transaction consumes the nonce, claims the grant, charges count/bytes and saves one exact fake consumption plan |
| Submission | Durable `SUBMITTING` plus attempt count before fake effect; lost reply becomes `UNKNOWN`; neither state permits another submission |
| Reconciliation | Two current fake observations must agree on exact issuance and consumption commitments with sufficient selected-chain successors |
| Response | One stored placeholder and digest committed before retrieval; a permanent possible-disclosure flag is set conservatively at commit |
| Retrieval | New purpose-separated signed challenge binds original request and response digest; returns identical stored bytes without another quota charge |
| Reorg/revocation | Blocks eligibility without rolling back the saved response, used grant, consumption plan or budget charge |

All signature domains start with `icp/model-release/v0/`. The network is the
deliberately artificial `testnet-10-model`; outpoints/consumption IDs start with
`model:`. Only the exact `FakeChain` adapter type is supported. No fake plan is a
native transaction or an input to the funded anchor pilot. Existing lab-v0
signatures are not release approvals. This experimental representation does not
adopt the draft's eventual R0 wire format or cryptographic delivery suite.

The unique fake key tag models a registration constraint. It cannot prove that
real content keys are fresh. Delivery/controller tags are public labels, not
usable recipient encryption keys, native P2PK scripts or proof of possession.
The draft's existing-envelope commitment is represented only by immutable
record metadata here; native issuance/consumption validation remains future work.

## State and clocks

The ordinary path is `ISSUING`, `ISSUED`, `RESERVED`, `SUBMITTING`,
`AWAITING_CHAIN`, `RESPONSE_COMMITTED`. A lost fake submission reply leaves
`UNKNOWN`; a crash after the durable submission intent can leave `SUBMITTING`
even when no effect happened. Reconcile the original saved plan. The model
deliberately favors at-most-one attempt over automatic recovery of availability.
Repeated response commits preserve the original bytes. A delayed submission
reply cannot regress an already committed response to `AWAITING_CHAIN`.

Count and original ciphertext bytes (including the encryption tag) are charged
at reservation in the fixed aligned window
`floor((reserved_at - origin) / window)`. The deadline is the minimum of the
grant expiry, original request challenge expiry and original window end.
All endpoints use strict `now < deadline`; retries never extend it. Later
windows can serve other grants but retain every previous charge. Timeout,
reorg, revocation and failed delivery never refund quota automatically.

The trusted clock is checked at transaction entry and before commit. Chain
freshness is checked at both points for chain-gated operations. A clock error
or backward movement latches a durable halt; reopening does not clear it.
Rejected operations preserve the latest observed clock while rolling back
their grant/nonce/quota changes; denial must not hide a later backward jump.
`halt()` also records explicit continuity uncertainty. Status/outbox reads remain
available for inspection. There is intentionally no automatic reset, epoch
rotation, database migration or unhalt API; a reviewed recovery procedure is
required before operational use.

Retrieval rechecks the gates after committing its nonce claim. Expiry or reorg
detected then blocks the return, although the challenge remains spent. A new
challenge can retrieve the same bytes if the original gates become valid again.
The model limits challenges to 64 total per grant to bound local storage; this
is an experimental availability limit, not a production rate-limit design.

## Trust and failure limits

The service process, record registration, operator methods, database, filesystem
and clock are trusted. Model calls are local Python APIs, not an authenticated
network service. SQLite `BEGIN IMMEDIATE`, uniqueness constraints and
`synchronous=FULL` serialize writers of **one database**. Tests include actual
subprocess termination around response commits; they do not establish hardware
power-loss behavior or remote database guarantees.

Copying or restoring the database defeats global uniqueness. An explicit
counterexample test copies an unclaimed database and successfully claims the
same grant independently in both copies. This implementation cannot detect
that operation. Writer fencing, anti-rollback storage, recovery audit and
multi-host continuity remain gates, as does authenticated policy rotation.
An abrupt process/host failure cannot durably record a clock sample it never
committed. Clock continuity across that gap is a trusted operational assumption;
reconcile uncertainty and halt before resuming.

`FakeChain` is trusted mutable test input. Two model views are not independent
nodes, operator ownership evidence, consensus proof or finality. Removing either
issuance or consumption blocks dispatch; exact reacceptance can restore it
within the original deadline. A reorg **after the final successful sample** can
still precede delivery. A counterexample test intentionally permits the
placeholder return at that boundary and preserves the possible-disclosure flag.
No database transaction makes chain observation and external delivery atomic.

The placeholder is neither an encrypted content key nor a signed service
attestation. Anyone with database/process access can see it. Production delivery,
key management, recipient registration/proof of possession, native transactions,
refund/fee rules, bounded wire parsing, independent review and the draft's other
gates remain unimplemented. One grant would never prevent later copying or
decryption by a recipient that already obtained a real content key. There is no
mainnet-readiness, global-security or quantum-safety claim.

See [verification](../evidence/release-ledger-model-verification.md) for the
adversarial coverage and checkpoint counts.
