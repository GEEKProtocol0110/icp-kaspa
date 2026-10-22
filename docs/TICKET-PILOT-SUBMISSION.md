# P0 submission journal experiment

[Project home](../README.md) · [Preparation gates](TICKET-PILOT-BINDING.md) · [P0 observer](TICKET-PILOT-OBSERVER.md)

When a send times out, the transaction might already have reached the network.
The controller must remember that attempt and check what happened before doing
anything else. This experiment adds that durable history to the private P0
preparer. Its transport is explicitly simulated: it makes no network calls.

## What is implemented

`scripts/ticket_pilot_submission.py` exposes a distinct controller policy and
one closed `SimulatedTransport` type. No live adapter, broadcast CLI, automatic
retry, fee replacement or journal migration is included. The existing offline
and observation-bound preparation variants keep their original behavior.

| Operation | Behavior |
| --- | --- |
| `submit_simulated('issue')` | Reverify saved native outbox and fresh exact source metadata; save submission intent before the simulated effect |
| `submit_simulated('terminal')` | Require a local issuance attempt, the permanent selected branch, its saved outbox and fresh exact unspent-ticket metadata |
| After intent commits | Acquire a new generation-checked lease, reverify all history and recheck fresh observations before one transport call |
| Reply received | Save only `REPORTED_ACCEPTED`, `REPORTED_REJECTED` or `UNKNOWN`; none establishes confirmation or permits retry |
| Exception or process death | Keep the same intent; a missing reply means uncertain outcome, even if no transport call occurred |
| Repeated submission call | Refuse with recovery required; never send, sign again, reset or switch branches |
| `reconcile_submission(phase)` | Read the current pinned tracker pair under the lease; return a revocable observation, without a send or signature |
| Recovery | Verify both component histories against the independent authority; preserve attempts/outboxes and invalidate observer eligibility |

The submission journal is a separate private `submission.sqlite` component
alongside `pilot.sqlite`, checkpointed by the same independently stored trusted
authority. The shared permanent source registry is retained. Its policy binds
the complete public review, native reviewer/worker fingerprints, observation
pair, claim-store path and simulated transport descriptor. Another controller
variant or transport configuration cannot silently reopen it.

Each phase has at most one immutable intent binding the exact saved record's
SHA-256, transaction ID and action. Its reply can be recorded once. Both
journals are checked on every operation. A restored component behind an
acknowledged authority checkpoint halts; an unacknowledged committed event is
reconciled through recovery. No absent store is silently recreated on reopen.

The writer lease remains held across the simulated effect and reply save.
Reopening the service between reservation and effect fences the old writer.
The final observation check follows native verification, copying the saved RPC
and transport-policy checks. Slow work cannot reuse an earlier eligibility
timestamp. A process death after the intent commits, or after the effect but
before reply persistence, leaves a nonretryable attempt.

## Reconciliation and chain changes

Run `recover()`, refresh both configured observers and explicitly call
`reconcile_observations()` before new work or submission reconciliation. That
refresh may use existing read-only `poll_pair`; tests use fabricated pages.
Reconciliation accepts current tracker handles, never copied positive status.
It does not write a permanent confirmation flag.

For issuance, current paired issuance with an unspent ticket, consumption or
refund provides the corresponding issue observation. A terminal phase requires
the exact selected consume/refund projection. An opposite terminal branch does
not confirm the selected branch. Stale/unavailable/conflicting observations
block reconciliation; a current unspent input returns false for acceptance.

These are native transaction-ID and reviewed field/layout observations, not
comparison of on-chain bytes to the full signed outbox hash. The observer
checks P0 compute/storage fields and relies on trusted nodes for signature
acceptance. A positive result is revocable when the chain reorganizes.
Reorgs preserve local attempt, branch and signed-outbox history; a later false
result never grants retry permission.

Historical status contains intent digests/IDs/actions and normalized replies,
with `retry_allowed=false`, `live_broadcasts=0` and no signed RPC or key. It is
not a current-chain proof or an authorization receipt. The reconciliation
response separately labels its scope `REVOCABLE_TRUSTED_NODE_OBSERVATION` and
records the time checked. A simulated acceptance reply alone yields no positive
chain observation.

## Verification and limits

```sh
cargo build --locked --features live --example ticket_read --example ticket_pilot_review --example ticket_pilot_private
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_ticket_pilot_submission.py' -v
```

Tests use real offline native signatures with temporary unfunded keys,
fabricated input/node evidence and simulated transport. They include actual
process deaths before the effect and after a durable effect marker, lost
acknowledgments, restored stores, stale writers, timeouts and reorgs. They do
not demonstrate a live P0 lifecycle or network submission.

The trusted local host, code, clock, authority, claim registry and node views
remain assumptions. Direct key/worker/transport access bypasses this policy.
Distinct node hosts do not establish operator independence. The policy supplies
neither grant/recipient authorization nor quota accounting or data-key delivery.

Two explicit counterexamples remain: a chain change after the final sample can
precede the effect, and jointly restoring the authority with all private stores
can lose an attempt and repeat the same simulated effect. At most one call is
enforced only within the trusted controller and surviving authority history;
there is no global exactly-once or production anti-rollback guarantee.

Next implement and independently test a bounded TN10-only native transport with
endpoint/network/build pins, exact saved-RPC submission and no automatic retry.
Keep live attempt records in a separate policy namespace from this simulation.
Verify operational role-key backup and possession before requesting funds for
independent consumption and unused-refund pilots. No operational key generation,
funding request or P0 broadcast was performed here.

The later [native adapter](TICKET-PILOT-LIVE.md) implements that TN10 network
capability under a distinct live policy, with offline test evidence. This
simulation variant and its existing journal identities retain their behavior.

[Verification record](../evidence/ticket-pilot-submission-verification.md)
