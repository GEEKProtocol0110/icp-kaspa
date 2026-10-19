# Native read tickets: issue, consume and refund

[Plain-English introduction](PLAIN-ENGLISH.md) · [Documentation](README.md) · [R0 draft](READ-TICKET-RELEASE-DRAFT.md)

**Status: offline engineering proposal. No ticket builder, signer, observer or
refund controller is implemented by this document.** Existing custody contracts,
lab encodings and funded sessions are unchanged. This selects a bounded first
native experiment under the [release-service design](RELEASE-SERVICE-DESIGN.md);
it does not adopt the complete R0 wire protocol or authorize a funded run.

The subsequent [native ticket lab](NATIVE-TICKET-LAB.md) now implements an
offline native layout/signature experiment with fabricated inputs. It has a
separate lab encoding, invented evidence digests and no durable branch
controller, authorization or live observation. The N0/R0 gates below remain.

A subsequent [fixture controller](NATIVE-TICKET-CONTROLLER.md) now tests
persistent branch/outbox recovery using a trusted local authority and synthetic
views. It supplies no real authorization or independently enforced native signer.

## In plain English

A service would create a small testnet output as a ticket for one approved
request. The recipient would prove who they are and which encryption key they
control. The service would reserve that ticket, spend it in one exact
transaction and check its acceptance before preparing a delivery.

An expired or revoked ticket that was **never reserved** could instead return
its test coins to a preset address. This refund would not return any data,
reset a limit or create a replacement ticket. A ticket already reserved for
release would have no refund path in this first experiment.

Kaspa enforces ordinary spending authorization and conflicting-spend rules.
The trusted service enforces permission, deadlines, budgets and the choice
between consumption and refund. A controller holding the spending key could
sign other spends; this P2PK proposal does not put those service rules into
consensus. A compromised release vault could disclose a key without a ticket.

## 1. Native facts and selected boundaries

Use the rusty-kaspa revision pinned by [TOOLCHAIN.json](../TOOLCHAIN.json),
`a41a333b08848f41bf737b72592e463a6011b8ac`. This proposal derives its transaction
requirements from that source, rather than assuming Bitcoin serialization:

| Source at the pinned revision | Relevant behavior |
| --- | --- |
| [Native signature hashing](https://github.com/kaspanet/rusty-kaspa/blob/a41a333b08848f41bf737b72592e463a6011b8ac/consensus/core/src/hashing/sighash.rs) | `SIG_HASH_ALL` binds the input outpoint, spent amount/script, sequences, outputs, locktime, subnetwork, gas and nonempty payload. V1 compute budgets are not part of that signature hash. |
| [Transaction hashing](https://github.com/kaspanet/rusty-kaspa/blob/a41a333b08848f41bf737b72592e463a6011b8ac/consensus/core/src/hashing/tx.rs) | V1 transaction ID combines payload and body digests; excludes signature scripts, storage mass and input compute budgets. An ID alone does not identify every saved transaction field. |
| [Standard scripts](https://github.com/kaspanet/rusty-kaspa/blob/a41a333b08848f41bf737b72592e463a6011b8ac/crypto/txscript/src/standard.rs) | Native Schnorr P2PK uses a pushed 32-byte public key followed by `OpCheckSig`; it contains no release-policy or refund-time predicate. |
| [Existing anchor preparer](../examples/prepare_transfer_anchor.rs) and [network guard](../src/lib.rs) | Existing project machinery checks TN10, exact P2PK UTXOs, storage mass and VM signatures. Its single self-return output is insufficient for the issue layout below. |

Implementers must recheck these source assumptions on dependency changes.
Do not hand-roll Kaspa transaction IDs or confuse them with the full native
transaction hash or an application SHA-256 digest. Preserve and check all three
where applicable. A service checksum is a continuity check, not authorization.

The first profile has three distinct native roles: funding `F`, ticket
controller `T` and return destination `R`. Their valid x-only Schnorr public
keys and exact P2PK scripts are pinned in policy. These roles are separate from
Ed25519 service/approval/recipient identities and X25519 delivery keys; never
reinterpret those key bytes as native spending keys. Native signatures have no
implicit TN10 domain: enforce network identity at every effect boundary.

No covenant, independent timed recovery key, fee replacement, batching, extra
inputs, arbitrary destination, key rotation or mainnet mode is selected.
P2PK ticket-key loss leaves the ticket unavailable; neither the refund authority
nor the funding key can spend it without `T`.

## 2. Candidate transaction profile N0

All amounts are integer sompi. This is an experimental economic profile, not a
current fee quote, mass benchmark or guarantee of node acceptance. A future
preparer must reject insufficient mass/fee/standardness conditions; it must not
silently change the approved layout or fee. Any revised profile needs new
approval, a new identifier and tests before signing.

| Field | Issue | Consume | Refund |
| --- | --- | --- | --- |
| Version / subnetwork / gas | `1` / native / `0` | Same | Same |
| Inputs | Exactly one pinned ordinary non-coinbase P2PK funding outpoint owned by `F` | Exactly ticket outpoint `issue_id:0`, owned by `T` | Same ticket outpoint |
| Input sequence / locktime | `0` / `0` | `0` / `0` | `0` / `0` |
| Compute budget | Exactly `100` for the sole input | Same | Same |
| Output 0 | `12,000,000` to `T` | `10,000,000` to `R` | `10,000,000` to `R` |
| Output 1 | Funding amount minus `14,000,000`, to `F` | Absent | Absent |
| Fixed fee | `2,000,000` | `2,000,000` | `2,000,000` |
| Payload prefix | `ICP-RT-ISSUE-TN10-N0\0` | `ICP-RT-CONSUME-TN10-N0\0` | `ICP-RT-REFUND-TN10-N0\0` |
| Signature | `F`, native Schnorr `SIG_HASH_ALL` only | `T`, same hash mode | `T`, same hash mode |

The displayed `\0` means one NUL byte. Append exactly one raw 32-byte commitment
digest to the ASCII prefix, with no trailing data. All output covenant bindings
and spent UTXO covenant IDs must be absent. Scripts must equal the pinned
script version and bytes, rather than matching an address label alone.

Issue funding must be between `24,000,000` and `100,000,000` sompi inclusive.
Thus its change is at least `10,000,000`; ticket and change indexes never swap.
There is no automatic coin selection, external fee input or dust donation.
Each lifecycle pays at most `4,000,000` sompi for issue plus **one** terminal
spend under this profile. That excludes prior funding and later return spends.
The returned P2PK coins are unrestricted by ICP after that terminal spend.

Sequence and locktime zero deliberately provide no native expiry or refund
delay. Service UTC deadlines and selected-chain successor counts have separate
meanings; neither becomes a consensus deadline by being included in a payload.
A previously signed spend may be submitted after service expiry. Expiry blocks
release decisions, rather than making those native signed bytes invalid.

Before signing, the future preparer must validate the complete approved plan,
exact spent UTXO amount/script/covenant/coinbase facts and role key, calculate
storage mass with the pinned library, sign and execute the native VM. Preserve
the entire final transaction, input entry and signature, recompute its ID and
full native hash, then durably save before any submission. VM success alone
does not prove acceptance, current UTXO state or appropriate relay fees.

## 3. Commitments without circular transaction IDs

This is a proposed new `icp-native-ticket-n0` namespace. Existing anchor/lab
payloads, signatures, binding certificates and synthetic IDs are not N0
permissions or native ticket evidence. No content key, private key, plaintext,
private vault handle or encrypted key response belongs in a public payload.

For proposed commitment bodies, `C(x)` is ASCII JSON with keys sorted, compact
separators, no whitespace and no alternate encodings. Closed schemas reject
unknown/duplicate keys, floats, booleans in integer fields, non-ASCII strings,
noncanonical hex and integers outside `0..2^53-1`. Encoded bodies are at most
16,384 bytes. Amounts/times/indexes are JSON integers; times are UTC Unix
seconds; digests/transaction IDs are 64 lowercase hex characters. The exact
closed schemas, signature domains and interoperable vectors must be frozen
and tested before a builder can accept this profile.

For action `a` in `intent`, `issue`, `consume`, `refund`, define
`H_a(x) = SHA256(ASCII("icp/native-ticket/n0/" + a) || 0x00 || C(x))`.
Commitment hashing and native transaction hashing are different operations.
Every body includes its namespace, action and network, plus the following:

| Body | Complete semantic binding required in its closed schema |
| --- | --- |
| Intent | Fresh private random 32-byte nonce; stable service/budget/grant; complete policy digest/epoch; immutable record/ciphertext commitment and size; signed-envelope commitment; recipient identity and exact delivery-key certificate/suite/epoch; `F/T/R` scripts/keys; N0 profile; original not-before/expiry; max uses one; approver/sender identities |
| Issue | Intent digest; digest of exact dual-signed intent approval; exact existing funding outpoint, amount and script; ordered output values/scripts; fixed fee/profile |
| Consume | Intent and issue commitment digests; exact issuance binding including ticket outpoint/value/script; original dual approval and recipient admission digests; delivery binding; stable service/budget/grant; policy epoch; original charged window/deadlines; exact return script/value and fee/profile |
| Refund | Intent/issue digests and exact issuance binding; stable operation; accepted permanent closure digest/sequence and reason; digest of separately authorized cleanup approval; exact return script/value and fee/profile |

An issuance binding records the locally recomputed native issue ID, output
index `0`, value and script after preparation, before submission. Acceptance
is tracked separately and revocably. The intent and issue body contain **no
future issue ID**. Recipient admission happens after issuance and binds that
known outpoint. Its challenge does not contain a future consume ID. Consume
and refund bodies contain no own future ID. Response context binds the known
consume ID after preparation. Do not hash a response into its own statement.

Approver and sender must sign the same complete intended authorization under
new purpose-separated domains. A digest reference is insufficient unless its
exact verified preimage is retained. Recipient authentication must bind the
intended permission, issuance binding, delivery certificate and original
request; a captured signature on an unrelated challenge is insufficient.
Refund approval is separate from permission, revocation and recipient requests:
policy must pin a distinct cleanup-administration identity. Its signed object
binds the full refund body except its own approval digest, which is added only
after signing. It cannot approve a release or replace the return destination.

Public action prefixes, reused controller/return scripts and input/output links
leak activity and linkage even if preimages stay private. The private random
intent nonce prevents simple low-entropy record guesses against deterministic
commitments, but does not provide transaction anonymity. Disclosure of audit
preimages requires separate metadata review and authorization.

## 4. Durable lifecycle and the refund decision

Keep reversible accepted-chain views separate from the irreversible operation
ledger and independently acknowledged checkpoints. Stable operation identity
is `(service_id, budget_id, grant_id)` across policies and writer generations.
Permanently claim the funding outpoint before issue signing and ticket outpoint
before either terminal branch. A copied SQLite claim file is not fencing.

| Durable transition | Required atomic ledger decision before the next effect |
| --- | --- |
| New to `ISSUE_INTENT` | Verified exact intent/approvals, unique grant and funding claim, immutable issue plan |
| `ISSUE_INTENT` to `ISSUE_PREPARED` | Exact final signed transaction, native ID/full hash and plan/bytes digests, issuance binding |
| `ISSUE_PREPARED` to `ISSUE_SUBMITTING` | One submission intent, checkpoint acknowledged before calling the broadcaster |
| Currently eligible issuance to `RELEASE_RESERVED` | Authenticate recipient; consume nonce; atomically claim ticket, charge original fixed window/count/bytes, select permanent `CONSUME` branch and save complete consume plan |
| Never-reserved issued ticket to `CLOSED_UNUSED` | Expiry or accepted revocation; permanently deny release/reservation, retain closure reason/sequence and ticket claim, select `REFUND` branch |
| `CLOSED_UNUSED` to `REFUND_PREPARED` | Separately verified cleanup approval, exact final signed refund and outbox with continuity acknowledgment |
| `RELEASE_RESERVED` to `CONSUME_PREPARED` | Exact final signed consume and outbox with continuity acknowledgment |
| Either prepared terminal spend to `*_SUBMITTING` | One durable submission intent and acknowledged checkpoint before external effect |
| Fresh eligible consume to response processing | Existing private prepare/commit/dispatch gates; never triggered by refund acceptance |

Reserve and close must serialize under the same enforcing authority. If
reservation wins, closure/revocation can stop release but cannot select refund.
If unused closure wins, reservation is permanently denied even if the refund
is never signed or later reorganized out. There is no branch switch on timeout,
lost reply, backup restore, key change or policy epoch.

Refuse signing both terminal spends, even when neither was broadcast. Signed
transactions are effect capabilities: deleting one does not prove no copy
survives. A live signer must enforce the permanent branch and operation context
at its own protected boundary, with independent continuity and current fencing.
A coordinator-only check is insufficient; Kaspa cannot enforce a service lease
or retract signed bytes held by an obsolete writer. This deployment gate is
unimplemented. A compromised `T` can still bypass it with another spend.

Refund is available only for a positively reconciled accepted issuance with a
currently unspent exact ticket, never reserved, no consume plan/signature/
submission/response history, permanent unused closure and fresh cleanup approval.
Approval loss or key loss blocks cleanup. An unknown issuance remains read-only
reconciliation until the exact transaction and output are established; it must
not produce an assumed refund or replacement funding transaction.

A reserved grant that expires, is revoked or whose consume transaction never
confirms retains its charge and claim. This deliberate availability cost
avoids introducing conflicting terminal outboxes in N0. Recovering its test
coins later requires a separately specified administrative design. After
successful consumption, test coins already return to `R`; no second refund is
created. Cash recovery never erases a possible disclosure or replenishes quota.

## 5. Submission, observation and recovery

Each action gets one immutable signed outbox and at most one routine submission
attempt. Persist `*_SUBMITTING` and obtain continuity acknowledgment first.
Timeout, process death or uncertain acknowledgment means outcome unknown; even
absence from the mempool or sampled chain does not prove a packet was unsent.
Recovery performs reads only. No automatic replacement, fee bump, re-signing,
rebroadcast, source reuse, new ticket or terminal-branch switch is allowed.
An explicit future rebroadcast policy would need its own reviewed gate.

The future N0 observer needs a separate schema from `AnchorTracker`. It must
support issue's two outputs and consume/refund's one output, rather than simply
removing the anchor's output-count guard. Two pinned distinct TLS endpoints
must each check network/health/activation, replay complete accepted-chain data
from a pinned bootstrap, apply removals, reach the sampled sink and report:

- Exact native transaction ID **and** full semantic layout/payload, version,
  subnetwork, gas, sequence/locktime, all spent outpoints, output indexes,
  amounts, scripts and absent covenant bindings.
- The terminal input's link to the accepted issuance. Before reservation or
  cleanup signing, both views also report the exact ticket currently unspent.
  After consumption, require its exact accepted spend, not an unspent ticket.
- At least ten selected-chain successors after the accepting block of each
  required transaction on each endpoint. Ten is a provisional experiment
  threshold inherited from the anchor, not calibrated finality or a time SLA.
- Fetch-start time, sampled sink, completed cursor and scan freshness at every
  preparation/commit/dispatch boundary. Use the service's existing trusted
  clock discipline; unresolved skew/continuity, backlog or missing history blocks.

Full saved signatures, compute budgets and mass remain private outbox integrity
checks. An accepted transaction with the same ID need not have byte-identical
signature/mass fields; do not claim the chain certified the local byte digest.
Observer comparisons must distinguish ID-bound semantics from fields outside
the ID and document any permissible native representation differences. An
unexpected semantic spend of the ticket permanently blocks release pending
explicit reconciliation; it is never treated as consumption or refund success.

The two views need not have identical tips or successor counts; each must
independently satisfy the same exact transaction predicates. Disagreement,
staleness, missing/pruned history or one endpoint failing blocks eligibility.
Two endpoint URLs do not establish two independent operators, SPV or consensus
verification. Mempool submission replies never satisfy acceptance.

Reorganization revokes current issuance/terminal acceptance. Preserve original
outboxes, branch, claims, charges, closures and response/disclosure history.
The same consume can become eligible again only within all original deadlines
and gates; the same refund can be observed again without reopening a grant.
Restore behind or conflicting with independent checkpoints halts. Never roll
back the authority together with application stores or clear an unresolved
operation to make progress. A final observation cannot prevent a reorg after
authorization or erase a response already in flight.

## 6. Acceptance gates and next implementation

The first executable milestone is an **offline native N0 preparer and mutation
test suite**, using public fixture keys and fabricated UTXO entries. It must
have no RPC, broadcast, real data or connection to the release models. Public
fixtures are intentionally known; never fund their addresses.

The subsequent [lab](NATIVE-TICKET-LAB.md) now tests that milestone's native
layout/signature portion using a separate fixture encoding. Actual N0
authorization and durable branch control remain unimplemented. The next lab
step is a fixture-only controller with exact outbox and crash recovery.

| Adversarial case | Required evidence before progressing |
| --- | --- |
| Change output order/value/script, input, payload, network or profile | Preparer rejects mismatch; native VM rejects relevant mutations of a previously signed spend |
| Change V1 compute budget, storage mass or signature without changing ID | Test documents native hash/VM behavior; complete outbox checks detect local changes; no false claim of ID binding |
| Alternate sighash, malformed key, noncanonical plan, duplicate field or bool/float integer | Strict parser and signer reject; native serialization/commitment vectors agree |
| Intent/issue/consume includes its own future transaction ID | Reject schema; vectors demonstrate noncircular construction |
| Funding bounds, insufficient change, overflow or extra fee input | Reject before signing; exact positive outputs and arithmetic verified |
| Native controller signs arbitrary otherwise valid P2PK spend | Counterexample demonstrates service-policy boundary; never counted as valid release |
| Concurrent reserve/refund, crash before/after signing/checkpoint/submission | Later separate controller tests prove one durable branch/outbox; unknown effects reconcile only |
| Old writer or restored signer/coordinator | Later independent enforcement tests reject new effects; explicitly retain risk of previously copied signed transactions |
| Refund after reservation, consume attempt, response or possible disclosure | Refuse; preserve all quota and history, including after reorg/expiry |
| Accepted refund or unrelated spend presented as consumption | Later observer/release integration rejects; no response preparation or dispatch |
| Backlog, unavailable endpoint, reorg and deadline crossing | Later observer integration blocks gates and retains original claims/outboxes |

Offline transaction tests will not establish native mempool acceptance, practical
fees, chain-age/context validation, signer isolation or live race behavior.
After that milestone come a fenced durable native controller, dedicated
read-only N0 observation, reviewed wire/metadata/cleanup authority and fresh
TN10 acceptance. Real content-key ownership, authenticated remote transport and
protected delivery remain independent gates. No production, global read-limit,
post-quantum or independent-audit claim follows from this proposal.
