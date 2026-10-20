# ICP documentation

[Project home](../README.md) · [Plain-English introduction](PLAIN-ENGLISH.md)

New to ICP? Start with the plain-English introduction. It explains the vault,
recovery route and data-access research, with examples and a short glossary.
Technical guides below describe the exact behavior and its limits.

## Understand the project

| Guide | What you will find |
| --- | --- |
| [ICP in plain English](PLAIN-ENGLISH.md) | The idea, an example, common questions and terminology |
| [Architecture](ARCHITECTURE.md) | How contracts, monitoring, signing and experiments fit together |
| [Security target](SECURITY-TARGET.md) | Implemented protections, assumptions and comparison with the source paper |
| [Project status](../PROJECT-STATUS.md) | Latest checkpoint followed by earlier engineering milestones |
| [Developer handoff](ICP-Project-Handoff.md) | Operational context and remaining work for the next contributor |

## Check the testnet evidence

These records describe specific runs with test coins. They do not establish
production readiness or a performance guarantee.

| Record | What was exercised |
| --- | --- |
| [Protected recovery](ICP-Protected-Recovery-Live-Proof.md) | Recovery vault, separate cold key, early rejection and later payout |
| [Watchtower recovery](ICP-Watchtower-Live-Proof.md) | Approved withdrawal and automated recovery of an unapproved one |
| [Original vault](ICP-Testnet-Live-Proof.md) | Earlier withdrawal, delay and recovery lifecycle |
| [Transfer anchor](ICP-Transfer-Anchor-Live-Proof.md) | A data commitment recorded on TN10 and observed through two endpoints |

Automated checks are defined in the [verification workflow](../.github/workflows/verify.yml).
Additional transcripts and milestone reports live in [evidence](../evidence/).

## Build or operate the prototype

| Guide | Purpose |
| --- | --- |
| [Developer setup](QUICKSTART.md) | Install dependencies, build, run offline checks and prepare a fresh testnet session |
| [Original vault specification](VAULT-SPEC.md) | V0 rules and threat model |
| [Protected recovery specification](PROTECTED-RECOVERY.md) | V1 rules, roles and commands |
| [Watchtower guide](WATCHTOWER.md) | Approvals, monitoring, restarts and chain changes |
| [Signer deployment](SIGNER-DEPLOYMENT.md) | Restricted recovery signing and service supervision; separate-host acceptance pending |
| [Transfer-anchor pilot](TRANSFER-ANCHOR-PILOT.md) | Exact transaction preparation, submission journal and read-only reconciliation |

Read [AGENTS.md](../AGENTS.md) before changing code. Keep keys, live databases,
signed transaction outboxes and private backups out of the repository.

## Explore the data-access work

| Document | Stage |
| --- | --- |
| [Encrypted transfer lab](TRANSFER-LAB.md) | Local encrypted-message and receipt experiment; keys supplied separately |
| [Recipient-encryption lab](RECIPIENT-ENCRYPTION-LAB.md) | Local real encryption to a pinned delivery key with possession checks and signed receipts; no remote service |
| [Transfer anchor observer](TRANSFER-ANCHOR.md) | Trusted-node observation code, a synthetic demo and links to the later testnet run |
| [Release-ledger model](RELEASE-LEDGER-MODEL.md) | Local accounting/crash/reorg experiment; simulated chain data, no real key delivery |
| [Bound response lab](BOUND-RESPONSE-LAB.md) | Encryption-key possession check and durable service signatures over exact dummy responses; no content keys |
| [Signed coordinator lab](SIGNED-COORDINATOR-LAB.md) | Signed permissions, recipient challenges and revocations integrated with synthetic recovery; dummy responses |
| [Release-coordinator model](RELEASE-COORDINATOR-MODEL.md) | Separate fake vault/ledger/delivery recovery and independent checkpoint/fencing simulation; no real keys |
| [Read-ticket and key-release draft](READ-TICKET-RELEASE-DRAFT.md) | Proposed release protocol and unresolved implementation gates |
| [Private P0 preparation](TICKET-PILOT-PRIVATE.md) | Offline private signing, durable source/branch claims and saved-outbox recovery; no chain or submission |
| [Pilot preparation](TICKET-PILOT-PREPARATION.md) | Unsigned P0 public-input native previews and a concrete future pilot sequence; no funding or live execution |
| [Native ticket design](NATIVE-TICKET-DESIGN.md) | Proposed TN10 issue/consume/refund policy, permanent branch choice and recovery rules; native layouts tested separately in the lab |
| [Native ticket lab](NATIVE-TICKET-LAB.md) | Working offline native layout/signature experiment and mutation tests; fabricated inputs, no RPC or real authorization |
| [Native ticket observer](NATIVE-TICKET-OBSERVER.md) | Read-only native projections, exact UTXOs and reversible trusted-node history; synthetic evidence, no controller integration |
| [Observer/controller integration](NATIVE-TICKET-BINDING.md) | Current native observations gate the persistent fixture lifecycle; synthetic scans, no live ticket or real authorization |
| [Native ticket controller](NATIVE-TICKET-CONTROLLER.md) | Persistent fixture branch/outbox recovery with native verification, crash tests and synthetic views; no RPC or real authorization |
| [Release-service design](RELEASE-SERVICE-DESIGN.md) | Proposed key ownership, exact-response delivery, revocation, fencing and backup recovery; no implemented service |

For licensing and source provenance, see [NOTICE.md](../NOTICE.md),
[LICENSE](../LICENSE) and the [import record](IMPORT.md).
