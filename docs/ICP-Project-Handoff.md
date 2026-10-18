# ICP - Kaspa Development


**Status: VAULT AND WATCHTOWER LIVE TESTS PASSED ON TESTNET-10.**

## Current result

- Public repository: https://github.com/GEEKProtocol0110/icp-kaspa
- CrypTony requested public, open-source development and accepted hosting under
  Michael's account. The original implementation uses MIT; upstream licenses
  and the supplied papers retain their own terms. See NOTICE.md.
- Pre-publication source history is preserved in docs/history/pre-github.bundle;
  see docs/IMPORT.md. GitHub Actions reproduces the offline verification suite.
- The vault's initial live lifecycle passed, including an early payout rejection.
- The next live test approved one exact intent before broadcast and automatically
  recovered another unapproved intent in one attempt. The approved withdrawal
  completed after its delay. Both new vault outputs have exited.
- 54 local checks passed: 27 script tests, 3 network guards, 24 watchtower tests.
- Current total test balances across all session addresses: 2.80 test KAS.

## Read first

- docs/ICP-Watchtower-Live-Proof.md and evidence/watchtower-live.json.
- docs/WATCHTOWER.md for arming, exact-intent approval, dry-run/execute mode,
  durable outbox, reorg undo, bounded retries and operational limits.
- docs/ICP-Testnet-Live-Proof.md for the earlier vault lifecycle.
- docs/VAULT-SPEC.md for the limited custody threat model.

## Files and continuation

The source package excludes live private keys and operator databases. The
private session archive includes .secrets/keys.json and runtime/, including
runtime/watchtower-pilot/watch.sqlite and the completed journals. Restore only
in a private test environment; never publish that archive or use these keys
for real funds. The repository's .gitignore excludes all of those paths.

Native CLI additions: anchor, scan HASH (VSPC v2), descriptor, prepare-initiate,
prepare-recover, broadcast PREPARED.json; status/chain reads need no private key
file. The signer still loads conventional keys on the same test host.

Use scripts/with_proxy.py with ICP_UPSTREAM_URL for this environment's normal
proxy. Exact previously resolved public TN10 endpoints are recorded in evidence.
The native runner rechecks network identity and node health before broadcasts.
Do not rerun either completed live pilot directory. Inspect and reconcile first.
The watcher is not left running as an unattended hosted service.

## Remaining work

1. Verify the public repository's GitHub Actions result and keep its checkpoint
   current. The recorded 54-check local run and funded testnet evidence remain
   distinct from CI; CI does not sign or broadcast transactions.
2. Specify and implement a protected recovery covenant rather than a plain P2PK
   recovery address; isolate recovery authority and signer from the owner role.
3. Harden deployment: service restart/health, external alerts, database retention,
   deep-reorg/pruning reconciliation and bounded backlog processing.
4. Add fee estimation within the immutable cap and external adversarial review.
5. Keep data tickets, STARKs, DAG Zippers and STATIC as separately specified
   future components. No claim of mainnet or quantum-safe readiness.

## Earlier checkpoints (historical; superseded above)

# ICP - Kaspa Development


**Status: FIRST LIVE VAULT LIFECYCLE PASSED ON TESTNET-10.**

Michael sent 3 test KAS to the session funding address. The live pilot then
completed deposit, two withdrawal intents, early-execution rejection, pending
recovery and delayed payout. The final recovery and recipient UTXOs were
independently observed through a second synced TN10 node.

## Read first

- docs/ICP-Testnet-Live-Proof.md: readable results, IDs and limitations.
- evidence/live-pilot.json: primary-node actions, signed transactions,
  explicit rejection and accepted-chain output observations.
- evidence/second-node.json: final UTXOs independently observed.
- docs/VAULT-SPEC.md: exact limited threat model and lifecycle.
- README.md: reproduction commands and the optional proxy wrapper.

## Verified

- Real SilverScript bytecode, checksum-pinned compiler and Kaspa dependencies.
- 27 native script tests and 3 network guards passed after the live fee fix.
- Deposit: 6fad9be014203572f73694084411c90e6ca509744ab46a9bb0b8953b3175535e.
- Recovery: dc7f9a6643e7087014d571d8b3235e02f2af83e27c9b343cd2783d2954c4833d.
- Delayed payout: c6cade7b912ae57f9df3d9ab4bfa9ff0d9be8535459670be4f0f4f28810aa328.
- That same payout ID was explicitly rejected before maturity for sequence locks.
- Both vault UTXOs have exited. Remaining balances: recipient 0.96 test KAS,
  recovery 0.96, funding-address change 0.98; total 2.90 test KAS.
- Accepted transactions paid a total of 0.10 test KAS in fees.

## Live correction

The first deposit was explicitly rejected for a fee below the node's relay
minimum. Its funding UTXO remained unspent. Before any accepted deposit, the
runner fee and immutable contract cap were changed from 100000 to 2000000
sompi (0.02 test KAS), states were recompiled and all local tests rerun.
Preserve evidence/initial-fee-rejection.json. Delay remains 600 DAA units.

## Project and session

- Separate from Geek Protocol. Starting from the papers was authorized.
- No buddy repository/code was supplied; no GitHub repository exists yet.
- Source package: ICP-Testnet-Prototype.zip, excludes live keys.
- Private restore: ICP-Testnet-Private-Session.zip, includes .secrets/keys.json
  and runtime artifacts/receipts. Keep private and use only for test funds.
- The proxy-aware wrapper is scripts/with_proxy.py (websockets 16.0). In this
  environment the HTTP resolver returned 403, so ICP_UPSTREAM_URL was set to
  the previously resolved TN10 Borsh TLS endpoints. Primary was vector-10 on
  kaspa.green; independent check used muon-10 on kaspa.blue. Exact endpoint
  names are in the evidence. The native client rechecks the network before
  every broadcast.
- Do not rerun scripts/pilot.py against the completed journal. Inspect status;
  create a separate fresh session when repeating the funded lifecycle.

## Next engineering steps

1. Establish the author's ownership/licensing and a dedicated private GitHub
   repository if requested. Never publish the private session archive.
2. Implement the specified watcher: accepted-chain tracking, authorized-intent
   policy, reorg undo, alerts, inclusion monitoring and a declared recovery SLA.
3. Replace the prototype P2PK recovery exit with a separately specified protected
   recovery covenant, and separate keys/hosts.
4. Harden transaction building with fee estimation within the chosen cap,
   failure/retry reconciliation, broader node testing and external review.
5. Keep data-release tickets, proofs, DAG Zippers and STATIC as separate later
   workstreams with their own specifications.

This is evidence for this small prototype's live paths. It is not a security
audit, mainnet-readiness finding or proof of quantum safety. Recovery depends
on a surviving conventional recovery authority and timely inclusion. The test
keys share one host; no production key separation is implemented.

## Earlier checkpoints (historical; superseded above)

# ICP - Kaspa Development


Status: BUILT AND LOCALLY TESTED; LIVE FUNDED PILOT PENDING.

- Starting from the papers was explicitly selected by Michael.
- No buddy repository or code has been supplied; no remote repository created.
- Separate from Geek Protocol.
- Real SilverScript idle/pending bytecode compiled with checksum-pinned v1.0.0.
- Rust native transaction-script tests: 27 passed; network guards: 3 passed.
- Tests enforce the transaction input compute budget and exercise real signatures.
- Immutable policy changes, redirected outputs, excess fees, wrong signatures,
  replay, sequence bypasses and old-idle-deposit execution are rejected.
- Live node read succeeded: testnet-10, synced, UTXO indexed, server 2.1.0,
  virtual DAA 599928594. Evidence is in evidence/tn10-node.json.
- No deposit or covenant spend has been broadcast by this project.
- Live transaction acceptance, actual age rejection, fee/mass policy and
  confirmation remain unverified. No audit or quantum-security claim.

## Next concrete step

Send 3 TN10 test KAS to this fresh test-only funding address:

`kaspatest:qq78m9h93fp6sv8u235umkfvyfqljmqfzr5jnxhpumg64hw4sel8sg877542k`

Public addresses and the corresponding test-only local keys were initialized.
The source archive excludes live keys. A separate ICP-Testnet-Private-Session.zip
contains the session backup and must not be published or used for real funds.
To restore it, extract inside the project root with permissions preserved.

Once funded, run scripts/pilot.py from the project. It automates deposit, two
withdrawal intents, explicit early sequence-lock rejection, pending recovery
and delayed payout. It records node responses and exact accepted-chain UTXO
observations. It refuses to silently restart a partial pilot. An interrupted
pilot requires inspection of saved outpoints before further actions.

The tested environment used a proxy-aware local WebSocket relay to reach the
public Borsh wRPC endpoint from the official SDK resolver. The default native
client may need a directly reachable endpoint outside this environment.

## Scope

Three fixed conventional keys, one protected UTXO per transition, owner-signed
initiation, a new pending output, CSV on that pending output, owner-signed payout
to a pinned recipient, separately signed recovery to a pinned P2PK address,
positive output value and per-transition fee cap. Delay 600 DAA; fee cap
100000 sompi. Owner compromise is modeled; recovery-key compromise is outside
the target. All three roles share one host for testing, not production custody.

Watchtower automation and protected recovery covenants are next. Data release,
STARK proofs, DAG Zippers and STATIC are not implemented.

## October 16 research checkpoint (historical)

The following preserves the original research. Its PAUSED/no-code status has
been superseded by the October 18 checkpoint above.

# ICP - Kaspa Development

**Status: PAUSED - research and project setup only**  
**Last checkpoint: October 16, 2026 (America/Detroit)**

## Start here

Michael and his buddy want to explore bringing Internal Command Protocol (ICP) to life on Kaspa. This is a standalone project, separate from Geek Protocol. The buddy supplied the technical concept; his identity, existing repository, implementation status, and preferred collaboration arrangements have not yet been established.

The user explicitly paused development and requested a project folder so we can resume without losing our place. Do not interpret this checkpoint as approval to deploy contracts, spend funds, publish the buddy's work, or contact him. Resume implementation when Michael asks to continue.

**Next step when resumed:** establish whether the buddy has an existing repository or code, then specify the smallest covenant vault and its threat model before implementation. Preserve the original papers as source material; proposed changes below are engineering recommendations, not changes approved by their author.

## Project materials

- `INTERNAL_COMMAND_PROTOCOL_(ICP)_—_Technical_Whitepaper_v2.0.pdf`: primary source, four pages. Describes covenant custody, controlled data access, and encrypted off-chain payloads. Printed timestamp: September 29, 2026.
- `STATIC Protocol Technical Whitepaper v1.0.pdf`: related reference, four pages. Describes order intake, batch settlement, liquidity reserves, and a treasury. Printed timestamp: September 10, 2026.
- `ICP-Project-Handoff.md`: this checkpoint, review findings, open decisions, proposed roadmap, and research references.

Both papers were read in this conversation. ICP received the deeper follow-up review. No ICP or STATIC code was supplied, built, audited, or deployed. No claimed bounty outcome was independently verified.

## What ICP proposes

| Component | Intended role | Review assessment |
| --- | --- | --- |
| Covenant vault | Restrict destinations, delay execution, provide rapid recovery | Credible starting point; exact paths and security assumptions are missing |
| Controlled data access | Consume read tickets and restrict release rates | Requires persistent accounting and a trustworthy connection to the off-chain data service |
| DAG Zippers | Encrypt bulk data off-chain and govern key release through proofs | Key distribution and recipient confidentiality are not specified |

The central idea is useful: holding a valid spending key need not confer unrestricted control when the output's script also enforces destinations, delays, amounts, and successor states.

The paper does not yet establish its broader claims of protection after every credential is compromised, mandatory majority-hashpower attacks, guaranteed immediate finality, register-only plaintext processing, or complete post-quantum security.

## Engineering review checkpoint

### 1. Define the surviving authority

The most important unresolved issue is what remains trusted after compromise. If an attacker possesses every credential that a contract accepts, credential checks alone cannot distinguish the attacker from its legitimate owner.

Distinguish these cases explicitly:

- Spending key compromised; recovery authority remains secure.
- Spending and recovery keys compromised.
- Watcher or operator compromised.
- Recipient key compromised after payout.
- Conventional elliptic-curve signatures forgeable by a quantum adversary.
- All secrets compromised versus only the conventional signatures becoming forgeable.

A fixed recovery destination can constrain redirection. A public recovery trigger may protect destinations while enabling denial of service. An unrestricted migration path authorized by conventional keys can undermine the stronger quantum threat model. Key rotation also needs authorization that the attacker cannot forge. Protecting funds indefinitely and allowing their legitimate eventual use are separate requirements.

### 2. Anchor the timer to a new withdrawal intent

The paper's `input creation DAA + N` expression is ambiguous. If the input is the original deposit, an old deposit may have already satisfied the delay before the key is stolen. The intended waiting window should start from an accepted pending-withdrawal state that commits the amount and destination.

Kaspa's relative-lock implementation uses the spent UTXO's recorded DAA score. Specify exact lock semantics, sequence flags, boundary conditions, and the applicable network parameters. The paper's 18,000 blocks at 10 BPS is an approximate duration, not a universal wall-clock guarantee.

This is a design-level ambiguity, not a demonstrated exploit against ICP code.

### 3. Treat watcher operation as a security assumption

An eligible cancellation is not guaranteed inclusion. The design needs sufficient time for detection, response, broadcasting, inclusion, and confirmation confidence before withdrawal maturity. Model outages, isolation, congestion, fees, competing spends, and malicious cancellation.

The watcher also needs a policy for distinguishing legitimate withdrawal requests from requests signed by a thief. Consensus validity alone does not establish owner intent.

### 4. Complete the spending invariants

| Sketch in paper | Missing implementation detail |
| --- | --- |
| Output 0 retains the script | Preserve the protected value, bound fees, constrain additional outputs, specify state representation |
| Execution waits N | Identify the pending input and enforce real lock semantics |
| Cancellation waits less | Bind its destination, authority, amount, and effect on the pending branch |
| Record-release ceiling | Preserve global/windowed accounting; prevent bypass through splitting and parallel state |
| Valid hash-based proof | Pin the approved program and bind public outputs to this exact action and state |

Keeping a small output under the same script does not by itself keep the rest of the funds protected. Excessive fees are another potential value-loss path. Multi-input accounting, alternate entrypoints, migration paths, replay, integer limits, and proof binding need review.

### 5. Repair the quantum and finality arguments

- Mining seeks any hash below a difficulty target; it is not equivalent to finding one particular 256-bit preimage. The paper's `2^256 -> 2^128` discussion does not establish mining attack costs.
- A finite-depth reorganization is not universally restricted to attackers with majority hashpower. State a tolerated probability under a defined adversary and network model.
- Higher BPS alone does not multiply accumulated proof of work or establish a specific confidence threshold.
- The finality formula's coefficient is not derived or calibrated in the paper.
- A public bounty needs exact source, transaction IDs, scope, and outcomes. An unclaimed bounty is not a formal security proof.

### 6. Separate enclave isolation from register-only processing

AWS Nitro Enclaves isolate CPU and memory resources; this does not inherently make an application process plaintext only in CPU registers. Evaluate application buffers, libraries, logs, output channels, client endpoints, attestation, key delivery, rollback, and the hardware trust model.

Consensus can limit authorization tickets. It cannot erase plaintext after a recipient reads it, prevent that recipient from copying it, or by itself make an arbitrary off-chain service obey release limits.

### 7. Specify the encryption and release construction

Keep encrypted bulk files off-chain, but explicitly define:

1. Payload encryption and integrity protection.
2. Initial key generation and custody.
3. Authorized recipient identity and credentials.
4. Proof statement and public-output binding.
5. Private key delivery or derivation.
6. Replay prevention and object/version binding.
7. Reorganization and irreversible-disclosure policy.

If a key is derivable entirely from public chain information, other observers can derive it too. If an additional secret is required, its security belongs in the threat model. STARK verification does not automatically supply private key delivery. Once a decryption key is disclosed, a reorganization cannot make it secret again.

KIP-16 provides a concrete STARK-based RISC Zero path as well as Groth16. Proof-system availability does not establish that ICP's entire pipeline is post-quantum secure. Any post-quantum design must consider authentication, key establishment, payload encryption, commitments, recovery, and implementation parameters end to end.

## Proposed first milestone - not implemented

Build a small testnet covenant vault after specifying and agreeing on its threat model.

Conceptual lifecycle:

1. Deposit into a protected vault.
2. Initiate a withdrawal, creating a pending output with committed amount and destination.
3. Cancel the pending withdrawal into a defined protected recovery state, or execute after the delay.
4. Recover or rotate authority under a separately specified policy.

Start with one well-defined asset and network. Keep data-release machinery and advanced proofs as separate later workstreams. Do not label the prototype quantum-proof.

Candidate acceptance statement:

> Compromising the spending key cannot bypass the vault's destination and delay rules. Recovery remains available under explicitly stated authorization, monitoring, and consensus assumptions.

This statement is a target to test, not a verified property of an existing ICP implementation.

### Required adversarial cases

- Old deposit does not bypass a fresh withdrawal delay.
- Stolen spending key cannot redirect protected value outside permitted paths.
- Destination or amount cannot change after the withdrawal intent is committed.
- Early execution and lock-disabling flags fail.
- Cancellation consumes the correct pending state.
- Concurrent execution and cancellation follow defined boundary behavior.
- Multi-input and extra-output layouts cannot leak value.
- Fees cannot drain the vault through repeated or keyless paths.
- Replayed proofs, wrong program identities, and stale-state authorizations fail.
- Recovery and migration entrypoints satisfy the same declared threat model.
- Watcher outages and congested-network conditions are measured.
- Recovery and recipient compromise outcomes are explicitly documented.

## Proposed roadmap

| Stage | Deliverable | Completion evidence |
| --- | --- | --- |
| 0 - clarify | Existing-code inventory, author requirements, threat model, decision log | Agreed scope and trust assumptions |
| 1 - specify | Vault state machine and transaction layouts | Reviewable rules for every entrypoint |
| 2 - prototype | Testnet vault and watcher | Reproducible positive and negative transaction results |
| 3 - challenge | Adversarial testing and external review | Recorded findings, fixes, and remaining limitations |
| 4 - extend | Separately specified data access and private key delivery | End-to-end confidentiality and release tests |

No dates, budgets, mainnet readiness, or delivery promises have been agreed.

## Decisions still open

- Buddy's existing repository and implementation status.
- Author-approved scope, ownership, licensing, and publication preferences.
- Which credentials may be assumed secure in each threat model.
- Whether cancellation requires a credential or uses a fixed public path.
- Recovery destination policy and eventual safe payout policy.
- Exact state representation, supported asset, network, and pinned toolchain.
- Delay duration, confirmation policy, fees, and watcher operating model.
- Encryption/key-release mechanism and trust assumptions.
- Whether STATIC is a separate project or later consumer of ICP protections.

## STATIC - related reference only

STATIC proposes a substantially larger trading/settlement platform: isolated order-intent UTXOs, relayer batching, uniform pricing, collateral conversion, fee routing, continuous reserves, AMM graduation, and a treasury.

Initial review identified missing order-matching rules, partial-fill and cancellation semantics, shared-liquidity contention, bridge/source-chain risk, stablecoin backing and valuation, complete liability accounting, and reproducible performance evidence. A weighted average is not a complete auction algorithm. Stablecoin conversion does not automatically remove cross-chain risk.

If resumed separately, the suggested first proof of concept is a testnet spot market with one test pair, deterministic matching, settlement, cancellation, and refunds. No bridge, stablecoin, leverage, or performance guarantee has been implemented or agreed.

## Research references checked on October 16, 2026

These are research leads and source snapshots, not endorsements or pinned production dependencies. Recheck current versions and pin exact commits before implementation.

- Kaspa KIP-17, covenant/introspection specification: https://github.com/kaspanet/kips/blob/master/kip-0017.md
- Kaspa KIP-16, proof-verification precompiles: https://github.com/kaspanet/kips/blob/master/kip-0016.md
- Kaspa covenant state documentation: https://github.com/kaspanet/docs/blob/main/content/docs/toccata/covenant-state.mdx
- Kaspa locktime opcodes: https://github.com/kaspanet/rusty-kaspa/blob/master/crypto/txscript/src/opcodes/mod.rs
- Kaspa relative-lock validation: https://github.com/kaspanet/rusty-kaspa/blob/master/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs
- Published Kaspa Forge vault and recovery source: https://github.com/Kaspaforge/kaspaforge
- Published vault contract inspected for comparison, not an audited ICP dependency: https://github.com/Kaspaforge/kaspaforge/blob/main/contracts/vault.sil
- AWS Nitro Enclaves security model: https://docs.aws.amazon.com/enclaves/latest/user/security.html
- Quantum Bitcoin Mining, research on target-based search: https://pmc.ncbi.nlm.nih.gov/articles/PMC8946996/
- Conditions for Advantageous Quantum Bitcoin Mining: https://arxiv.org/abs/2110.00878
- NIST post-quantum standards announcement: https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved
- Ethereum bridge risk reference used for STATIC review: https://ethereum.org/en/developers/docs/bridges/

## Resume checklist

1. Read this checkpoint and the primary ICP whitepaper.
2. Ask for or inspect the buddy's repository if one exists; do not assume we are starting from zero.
3. Inventory actual code and pin relevant Kaspa/compiler versions.
4. Resolve the surviving-authority and recovery questions.
5. Turn the proposed vault lifecycle into a concrete specification before writing the first contract.

**Stopping point: project organized; research preserved; development paused at the user's request.**
