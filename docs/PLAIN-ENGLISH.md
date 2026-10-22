# ICP in plain English

[Project home](../README.md) · [All documentation](README.md) · [Developer setup](QUICKSTART.md)

**ICP adds withdrawal rules and a recovery window to a vault on Kaspa.**
Its longer-term research also explores permission checks before releasing
encrypted data. The vault prototype has testnet evidence; decryption-key delivery
for data access is still being designed.

## The problem it addresses

A stolen spending key can make a transaction look properly signed even when
the owner never wanted it. ICP explores an extra layer of rules: a withdrawal
must go to a preset destination and wait before it can complete.

During that wait, monitoring software checks the withdrawal against saved
approvals. If it finds an unapproved withdrawal, it can use a separate recovery
key to try to move the funds into a recovery vault.

Think of a timed vault with a separate recovery route. The waiting period
creates an opportunity to respond. It does not guarantee a successful response.

## An example

A team configures a vault with its normal payout destination, a recovery route
and separate keys. An attacker obtains the normal spending key and requests
a withdrawal.

The attacker still has to use the configured destination and wait. The monitor
can notice that the request has no saved approval and request recovery. If
the recovery transaction is accepted in time, the funds enter a recovery vault.
Releasing them from there requires a separate cold key and a longer wait.

These rules do not let the monitor know someone's true intentions. It compares
transactions with approvals that the operator has recorded. The approvals,
monitor, recovery keys and node connection must remain trustworthy and usable.

## What each part does

| Part | Everyday explanation |
| --- | --- |
| Vault | Funds held under rules enforced by the blockchain |
| Spending key | Starts a normal withdrawal |
| Watchtower | The monitor that checks withdrawals against saved approvals |
| Recovery key | Can move vault funds into the recovery route |
| Recovery vault | Holds recovered funds behind a cold key and a longer wait |
| Cold key | Authorizes release from that recovery vault after its wait |
| Kaspa node | Reports chain activity and checks whether a transaction follows the network's rules |

The current prototype uses different keys for different roles. Testing them
on one host does not establish that they are safely separated in a real
deployment. Separate-host operation still needs live acceptance testing.

## Where encrypted data fits

Imagine a service holding an encrypted document. The proposed data-access
system would check which recipient has permission, which exact record is
covered, whether permission has expired and whether a release limit has been
reached before delivering a decryption key.

Kaspa could record commitments and ticket transactions related to those
requests. Private documents and decryption keys would stay outside the public
chain. A proposed ticket controlled by an ordinary spending key would not
enforce all those permission rules by itself; the service would enforce them.

The local release model tests that a request cannot claim the same grant twice,
that crashes do not erase saved accounting, and that a chain reorganization
does not refund an already used grant. It uses simulated chain observations
and a non-secret placeholder instead of a real key.

A separate [recipient-encryption lab](RECIPIENT-ENCRYPTION-LAB.md) now encrypts
a fictional message to one pinned recipient key and checks the sender before
local decryption. An encrypted challenge checks possession of that recipient's
delivery key. It is a local cryptographic experiment, with no agency integration
or network delivery. It is not yet connected to the release model.

The [release-service design](RELEASE-SERVICE-DESIGN.md) describes keeping record
keys private, saving each authorized delivery before sending, and recovering
that same delivery after a failure. A new [recovery simulation](RELEASE-COORDINATOR-MODEL.md)
now tests those steps across separate fake vault, ledger and delivery stores.
An independent fake checkpoint store blocks old writers and detects older
component backups. Everything it delivers is a non-secret placeholder;
permission and recipient authentication are supplied by the test harness.

A separate [signed-request lab](SIGNED-COORDINATOR-LAB.md) now adds two
permission signatures, a fresh recipient signature before reservation/delivery,
and signed revocation. These checks run together with the recovery simulation.
The recipient is a configured signing key, while delivery-key ownership and
record/chain facts are still fixtures. No real decryption key is released.

The latest [key-binding and response-record lab](BOUND-RESPONSE-LAB.md) also
checks that the recipient can answer an encrypted challenge with the separate
delivery key. It saves a service signature with each exact dummy response, so
retries recover the same signed record. This encrypts the registration challenge
only; the returned placeholder bundle is public test data, not a protected
message or decryption key. Real key delivery is still future work.

The [native ticket proposal](NATIVE-TICKET-DESIGN.md) describes creating and
spending a small testnet ticket for a request. An expired or revoked ticket
could return its test coins only if it had never been reserved for release.
That refund would restore neither permission nor a release limit. This part
now has an [offline transaction lab](NATIVE-TICKET-LAB.md): working code builds
the transactions with made-up inputs and checks their signatures and layout.
It does not yet enforce the refund history rule or submit anything to Kaspa.

A separate [ticket controller](NATIVE-TICKET-CONTROLLER.md) now remembers that
choice and the exact saved transaction across crashes. It uses made-up chain
observations and checks recovery without moving coins or delivering data keys.

A separate [ticket observer](NATIVE-TICKET-OBSERVER.md) checks whether a ticket
was created, used or refunded. If the chain changes, its answer changes too.
Its tests use made-up chain records. The [connected controller](NATIVE-TICKET-BINDING.md)
now requires current matching observations before new work, while remembering
past choices and charges through a chain change. Real permission checks and
proving a live ticket lifecycle are still ahead.

The [pilot preparation tool](TICKET-PILOT-PREPARATION.md) now shows the exact
proposed transactions before they are signed. It uses public information only.
Separate tools now keep private signing/recovery records and record an attempt
before sending a testnet transaction. The [key setup tool](TICKET-PILOT-KEYS.md)
has prepared two fresh test sessions and verified their private backups: one
session will use a ticket, and the other will return an unused ticket's coins.
The next step is funding and checking those exact sources, then proving both
paths on Testnet-10. Public demo addresses must never be funded. Real permission
checks and private data-key delivery still need to be built and tested.

The older model allows copied databases to accept separate claims. The new
simulation adds a trusted witness, but restoring that witness with every
store still loses history. Both models also recognize that a chain change
or revocation after the final delivery decision cannot recall bytes. Real
release needs production safeguards, authenticated integration and review.

**One key release is not one viewing.** Once someone has a decryption key,
they can keep reading or copy the data. A later expiry or chain change cannot
take that knowledge back. A recorded commitment also does not prove that the
original document is factually true.

## How to read the project's results

| Label | What it means here |
| --- | --- |
| Tested on Testnet-10 | Transactions were submitted to Kaspa's test network using test coins; dated records show what was observed |
| Offline test | Code was checked locally or in automated builds without a new live transaction |
| Simulation or model | Invented chain observations or placeholders exercise the rules; they are not live-chain evidence |
| Proposal or research | A direction being specified; a working, secure deployment has not been established |

There are **970 automated tests** in the current inventory. Passing tests helps catch mistakes; it
does not replace an independent security review or prove production readiness.
The project is still an experimental Testnet-10 prototype.

## Common questions

**Does this protect every bank account or government system?**
Those are possible long-term applications. They would need authorized
integration with the systems that actually hold funds or control data. No such
deployment or customer is demonstrated here.

**Is recovery guaranteed?**
No. The monitor and recovery key must be available, and the recovery transaction
must be accepted in time. Once a normal payout becomes eligible, recovery has
no guaranteed priority over it.

**Do the waits mean an exact number of seconds?**
No. They use chain-based measurements. Actual elapsed time can vary.

**Do the vault rules follow funds forever?**
No. Once funds leave for the final normal or cold destination, this vault's
rules no longer constrain later transfers.

**Is this quantum-safe?**
Overall quantum safety has not been demonstrated. A separate
[message experiment](POST-QUANTUM-RECIPIENT-PROFILE.md) now uses hybrid
post-quantum encryption and post-quantum signatures. The vault and Kaspa's
native transaction keys retain their existing cryptography. An optional
[software keystore](PQ-ENCRYPTED-KEYSTORE.md) now encrypts new message keys
behind a passphrase. Compromised devices, weak passwords and copied replay
stores remain important limits;
the experiment does not promise protection if every accepted secret is stolen.

## A few terms you may see

| Term | Plain meaning |
| --- | --- |
| Custody | How funds are held and who can move them |
| Covenant | Blockchain rules restricting how particular funds may be spent |
| UTXO / outpoint | A particular unspent transaction output, identified by its transaction ID and output number |
| DAA units | A chain-based score used for the prototype's waiting periods; not a fixed number of seconds |
| Anchor / commitment | A short cryptographic fingerprint recorded on chain; it does not reveal the full document or establish its truth |
| Grant | Permission for one specified key-release request; not a limit on later reading |
| Reorganization / reorg | A change to the chain's accepted history that may change a transaction's observed acceptance |
| Durable ledger | Saved service records intended to survive a restart; copied or restored records still need safeguards |

For proof records, implementation guides and specifications, open the
[documentation directory](README.md). For exact security assumptions, read the
[security target](SECURITY-TARGET.md).
