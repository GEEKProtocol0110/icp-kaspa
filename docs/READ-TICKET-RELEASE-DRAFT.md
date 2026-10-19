# Read tickets and recipient key release: R0 design draft

The subsequent [synthetic ledger model](RELEASE-LEDGER-MODEL.md) tests a subset
of these state/accounting rules. It does not adopt an R0 wire/delivery suite,
create native tickets or implement real key release. This draft remains a
proposal; its unimplemented gates still apply.

**Status: engineering proposal, not implemented or an adopted protocol.**
This defines the next bounded experiment after the
[funded transfer anchor](ICP-Transfer-Anchor-Live-Proof.md). It changes no custody
contract, funded policy, receiver rule or existing lab encoding. Publication
does not establish review or approval by the source paper's author.

## Proposed target and enforcement boundary

One authorized grant may produce one durably committed encrypted key response
for one pinned recipient delivery key and one immutable encrypted record
version. Concurrent requests and restarts must resolve to that same grant.
New grants require their own explicit approval and consume the same service
budget. This is a limit on **key-release grants**, not on subsequent reads,
copies or disclosures by someone who already knows the key or plaintext.

R0 proposes a trusted release service plus a consumed TN10 UTXO as a chain
witness. A plain P2PK ticket is an intermediate experiment: its script alone
does not enforce approver policy, delivery identity, expiry or release limits.
The service enforces those rules. A later covenant/proof design must specify
its own authorization and shared-state transitions before claiming on-chain
enforcement. An arbitrary payload commitment is not an authorization.

| Component | Proposed responsibility | Trust assumption |
| --- | --- | --- |
| Data owner / encryption process | Fix the encrypted record version and put its key behind the release boundary | Already knows the data/key and can disclose it outside the protocol |
| Policy approver | Approve the exact grant, record, recipient delivery binding and budget | Conventional authority; signature possession is not proof of legitimate human intent |
| Sender | Co-sign the exact approved grant and encrypted exchange | Distinct from approver; cannot substitute a recipient or record |
| Recipient identity | Authenticate a fresh service challenge and bind its delivery key | Conventional identity key; distinct from the delivery key's purpose |
| Ticket controller | Sign the pinned issue/consume transactions | Separate Kaspa spending role; not the release-key authority |
| Release service / key store | Check policy, authenticate requests, own the grant ledger and wrap the content key | Trusted process, storage, clock and key-management boundary |
| TN10 endpoints | Report exact current issuance/consumption acceptance | Trusted RPC observations; no independent consensus verification |

A compromised service or content-key store can disclose keys without a ticket.
A forged approver/recipient authorization can satisfy conventional checks.
Compromise of every accepted secret is outside this proposed target. Neither
this service model nor a conventional ticket-controller key resolves the
[stronger security-target gates](SECURITY-TARGET.md).

## Objects and exact binding

Use a **new** R0 namespace. Existing `icp-transfer-lab-v0` signatures/receipts
cannot silently become R0 approvals. The current lab hands the AES key to its
caller; R0 needs a new ownership boundary that retains the content key at the
owner/service and does not pass it directly to the recipient before release.

Each independently authorized record version needs its own fresh content key.
Reusing a key across records or versions lets one grant unlock data outside its
intended scope. Recipient-specific wrapping does not repair that reuse. R0
grants access to the entire pinned ciphertext; field-level access needs separate
encryption scopes. A new version must not remain decryptable with an old grant's
key merely because its hash, nonce or associated data changed.

The proposed objects below must be covered by strict, bounded schemas. The
wire specification and cryptographic suite are implementation gates, not
implicit choices in this document.

| Object | Required binding |
| --- | --- |
| Policy | Network `testnet-10`, service ID, stable budget ID, policy epoch, all authorities, supported delivery suite, limits, clock/window rules, endpoint/confirmation policy and revocation authority |
| Record version | Public commitment to opaque record ID, immutable version, ciphertext hash/byte length and encryption context; a separate content-key reference stays private to the key store |
| Delivery binding | Recipient identity, delivery suite, exact public-key digest, registry/key epoch and approver authorization; a substituted key requires a new grant |
| Ticket intent | Random grant ID, policy digest/epoch, complete record commitment, existing signed-envelope commitment, recipient identity/delivery binding, controller public key, not-before/expiry and maximum use count of one |
| Issuance binding | Ticket-intent digest, exact accepted creation transaction ID, output index, value and script; pinned after preparation and before submission |
| Recipient request | Service ID, network, ticket-intent digest, known ticket outpoint, policy epoch, delivery binding, fresh challenge nonce, request digest and challenge expiry; signed by recipient identity |
| Consumption commitment | Exact ticket outpoint, ticket-intent digest, recipient request digest, delivery binding, stable grant ID, budget ID/window and policy epoch |
| Encrypted key response | Content key encrypted to the pinned delivery public key; authenticated context binds the record/ciphertext, grant, ticket outpoint, exact consume transaction ID, request, policy and service |
| Service attestation | Digest of the complete encrypted key response and its bound context, signed by the pinned service identity |

The ticket-intent digest cannot include its own future issuance transaction
ID: that would create a self-reference. First commit the intent, then bind the
prepared transaction's exact output. The consumption commitment can include
that already-known outpoint. Never insert a raw content key, private key,
plaintext record or private key-store reference into a public transaction.

The existing Ed25519 lab identities are not automatically Kaspa spending keys.
The R0 policy must explicitly bind a separate native ticket-controller key.
Plain P2PK signatures authorize spends; the release service must additionally
validate the off-chain approver/sender/recipient authorizations.

## Ticket issue, consumption and release gates

1. **Issue.** Validate the complete policy, immutable record and two-role grant
   approval. Reserve the grant ID against duplicate issuance before signing.
   Prepare a new, bounded TN10 transaction whose payload commits to the ticket
   intent and whose exact output is controlled by the pinned ticket controller.
   Persist signed bytes and the output binding before one submission attempt.
   Confirm that exact issuance/output on both pinned endpoints. The current
   self-return anchor is not retrospectively a read ticket.
2. **Authenticate and reserve.** Issue a bounded, expiring random challenge.
   Verify the recipient signature and exact delivery binding, active policy,
   unexpired grant and live unconsumed ticket. Atomically claim the grant,
   outpoint and challenge, charge its budget and persist the exact consumption
   plan/outbox. A conflicting request gets no key and no second consume plan.
3. **Consume.** Prepare a transaction spending exactly the ticket outpoint,
   with the exact consumption commitment, bounded fee and pinned return output.
   Persist its signed bytes before submission and pin its transaction ID.
   Unknown outcomes require read-only reconciliation; do not replace the
   transaction, change its recipient or allocate another grant automatically.
4. **Observe.** Both endpoints must currently report the same exact issuance
   and consumption bindings on their accepted branches, required selected-chain
   successors and fresh, caught-up scans. A mempool reply or unrelated spend is
   insufficient. A spend with the wrong commitment invalidates the ticket for
   release. DAA increments do not substitute for the chosen successor threshold.
5. **Commit the response.** Recheck challenge/grant deadlines, policy epoch and
   revocation, delivery-key binding, budget window and current chain evidence.
   Only then let the key store wrap the content key. Atomically store the
   complete response bytes, service attestation and irreversible grant-used
   record before returning any of those response bytes to a caller.
6. **Deliver.** Return only that stored encrypted response to the authenticated
   recipient while the same checks still permit dispatch. A retry returns the
   same bytes and consumes no new grant. After expiry/revocation/reorg, return
   status metadata without the encrypted key response. An optional recipient
   receipt remains a signed claim, not proof of decryption or deletion.

Retrieval retries use a fresh, purpose-separated challenge bound to the
original request and stored response digest. They must not replay the consumed
grant challenge, create another reservation or extend the original grant,
request or budget-window deadlines. The wire specification must distinguish
new-grant authentication from retrieval authentication explicitly.

Issue and consume transaction layouts, refund rules and fee policy need their
own native implementation/VM tests. The existing anchor preparer permits only
self-return funding and cannot be repurposed unchanged to issue a separately
controlled ticket. No funded R0 run is authorized by this draft alone.

## Durable states and irreversible history

Chain observations and disclosure history have different rollback rules.
Rollback may revoke current evidence; it must not erase a used grant, budget
charge or possibly exposed key response.

| State/event | Durable requirement | Permitted next action |
| --- | --- | --- |
| `ISSUING` / unknown issuance | Reserved grant ID and exact signed issuance bytes | Reconcile original transaction; no replacement ticket |
| `ISSUED` | Exact accepted ticket binding and still-unused grant | Authenticate recipient and atomically reserve |
| `RESERVED` | Unique grant/outpoint/request, challenge consumed, budget charged, consume plan pinned | Prepare/persist one consume transaction |
| `SUBMITTING` / unknown consumption | Exact signed consumption bytes and prior submission intent | Reconcile original transaction; no key response |
| `AWAITING_CHAIN` | Consumption not yet eligible under fresh evidence | Observe until eligible or halt/expire |
| `RESPONSE_COMMITTED` | Immutable encrypted response plus permanent used-grant record | Dispatch/retry identical bytes only while all gates permit |
| Reorg before response commit | Keep reservation, budget and original outbox | Await the same consumption's reacceptance within the original deadlines |
| Reorg after response commit | Keep used-grant record and response; flag possible disclosure | Stop dispatch; never refund/reissue; any resumed dispatch needs the same exact consumption reaccepted and all original gates |
| Expiry/revocation/invalid spend | Keep claims, charges and any committed response | Metadata/reconciliation only; no automatic replacement or key response |

A crash before the response transaction commits must expose no response bytes
through the API. A crash after commit but before delivery may leave delivery
unknown: recover the stored response, not a newly wrapped key or new grant.
Client acknowledgments do not make disclosure reversible. A reorg or revocation
after dispatch cannot erase a key already received or a message in flight.

The existing `AnchorTracker` rolls back observation history. It must not be
used as the authoritative irreversible release ledger.

No atomic transaction spans Kaspa, the service ledger and network delivery.
A reorg can occur after the final chain sample and before response dispatch.
Freshness/successor checks reduce exposure under the chosen observation policy;
they do not eliminate that race. Record possible disclosure when a later scan
reveals it, preserve the original grant and never compensate by reissuing a key.

## Replay and budget semantics

One fenced service authority owns one authoritative ledger. Across policy/key
rotation, retain uniqueness for `(service_id, budget_id, grant_id)` and the
claimed ticket outpoint. Retain used challenges and exact request/response
bindings. A new policy epoch must not reset old claims or counters.

Proposed first budget: fixed, UTC-aligned windows under the trusted service
clock. With pinned origin `origin` and positive duration `window_seconds`, the
window is `floor((reserved_at - origin) / window_seconds)` for nonnegative
offsets. Reserve one grant and the exact original ciphertext byte length,
including its authentication tag. All new grants in that budget share the
same count/byte limits, including grants for the same record or other recipients.
Persist the last accepted service time. A backward clock step or uncertainty
about clock/ledger continuity halts new reservations and dispatch until explicit
reconciliation; changing clocks or window parameters must not reset counters.

Reservation, limit checks, unique claims and the consume outbox are atomic.
Do not automatically refund a charge after timeout, expiry or reorg. Failures
can waste quota; that availability cost is deliberate for the first model.
Reconciliation must not silently turn wasted quota into a second authorization.
Before any response dispatch, require the original reservation window still
open as well as all grant/challenge deadlines. A boundary crossed while waiting
for acceptance halts release; it does not move the charge to another window.

The limit measures reservations/new logical grants under this service. It is
not a cap on packets, actual recipient reads, offline copies or physical
arrival time. Identical response retries do not create a new logical grant.
Even an expired in-flight message can arrive later. API dispatch deadlines do
not make a disclosed key cryptographically expire.

A cloned/restored ledger or two unfenced writers can invalidate these claims.
R0 must stop after suspected rollback or lost history. It does not establish
anti-rollback protection from SQLite durability alone. Specify backup recovery,
writer fencing and independent audit before any multi-host deployment. A
globally enforced on-chain rate limit requires a separately specified state
machine; per-service counters cannot be advertised as that limit.

## Acceptance cases before implementation is called complete

| Adversarial/failure case | Required result |
| --- | --- |
| Alter record version, ciphertext, delivery key, policy, service or network | Fail before consume submission or key-response dispatch |
| Reuse one record/version's content key for another authorization scope | Refuse registration; an old grant must not decrypt the new scope |
| Valid sender signature without separate approval; wrong recipient identity | No reservation or key response |
| Replay a challenge or race two requests for one grant/outpoint | One durable reservation/consume plan; no second grant |
| Same request after restart or lost response | Reconcile exact outbox; recover identical committed response only when still eligible |
| Mempool acceptance, stale/backlogged node, wrong accepted payload/output or one endpoint unavailable | No key-response commit/dispatch |
| Grant or budget window expires between validation and commit | Atomic commit refuses; no automatic quota refund/replacement |
| Crash at each persistence/submission/response boundary | No pre-commit response exposure; ambiguous chain outcome reconciled before further action |
| Rollback before/after response commit | Revoke current eligibility; preserve permanent claims/charges and possible-disclosure flag |
| Reorg after the final sample but before dispatch | Recognized observation race; later detection marks possible disclosure without refund/reissue |
| Rotate policy/delivery key or restore an older DB | No relabeling of old grants or counter reset; uncertain recovery stops |
| Recipient forges its own receipt without decrypting | Receipt remains a claim; no additional authorization is created |
| Caller already has the content key or service runtime is compromised | Documented boundary violation; do not claim policy can prevent decryption |

## Decisions still required and next deliverable

Freeze the following before implementing remote release or funded tickets:

- Exact signature/digest domains, strict schemas, canonical bytes, duplicate
  rejection, size bounds, timestamp units and cross-version replay tests.
- A reviewed recipient key-delivery suite, identity-to-key registration proof,
  authenticated context, malformed-key behavior and service attestation format.
  Signing-key bytes must not simply be reused as encryption-key bytes. No
  post-quantum suite, secure hardware or protected key-store implementation is
  selected or demonstrated here.
- Ticket issuance/consumption scripts and payloads, output/value/fee predicates,
  accepted-chain evidence, expiry/refund handling and key-loss procedures.
- Independent approval/revocation/rotation authority, service failure recovery,
  ledger fencing/anti-rollback policy, quota exhaustion and disclosure audit.
- Metadata review for public ticket/grant commitments, recipient linkage and
  object popularity. Encryption alone does not hide those access patterns.

Next deliverable: a synthetic-data-only local release ledger and fake-chain
adapter implementing these transitions and crash/concurrency/reorg cases.
It must remain clearly labeled a service-enforced model. Connect a real chain
adapter and recipient key-delivery implementation only after their separate
gates pass; do not reuse a dated anchor observation as a current access grant.
