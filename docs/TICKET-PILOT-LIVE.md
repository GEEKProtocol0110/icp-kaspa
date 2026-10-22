# P0 Testnet-10 submission adapter

The later [read-path repair](TICKET-PILOT-READ-PATH.md) passed a live two-node
funding-source preflight with no signatures or submissions. Use a new policy
with its pinned read profile/build; do not migrate the old halted preflights.

[Project home](../README.md) · [Submission journal](TICKET-PILOT-SUBMISSION.md) · [P0 observations](TICKET-PILOT-OBSERVER.md)

The private P0 controller can now call a native Testnet-10 sender. It saves one
submission intent before that call and keeps uncertain outcomes for read-only
reconciliation. This milestone implements the network capability; its tests
use fabricated observations, offline native verification and local pipe fixtures.
No successful P0 RPC submission or funded P0 lifecycle is claimed.

## Boundaries

| Component | Responsibility |
| --- | --- |
| `ticket_pilot_private` | Sign with supplied role keys and independently verify complete native records |
| `ticket_pilot_binding` | Check two pinned current observers before new preparation |
| `ticket_pilot_submission` | Checkpoint permanent attempts/replies and reconcile observations; its default transport stays simulated |
| `ticket_pilot_live.Controller` | Distinct live policy, explicit `submit(phase)`, same durable attempt/recovery rules |
| `ticket_pilot_live.Transport` | Pin the first observer endpoint, sender/relay paths and binary/source fingerprints; enforce bounded process I/O and termination |
| Native `ticket_pilot_submit` | Reverify the complete saved record, check network/input/deadline, call the ordinary submit API once with orphan admission disabled; no replacement API |

The new sender and existing private worker use one shared verifier in
`examples/support/ticket_pilot_verify.rs`. This preserves the existing private
wire format and complete signature/VM/layout/full-hash checks. Native submission
has no signing, key loading, key generation, coin selection or retry command.
Moving the verifier changes compiled build fingerprints: do not replace pinned
binaries under a running journal or silently relabel an old policy.

The live policy has a different identity and submission role from the simulated,
bound-preparation and offline variants. Those journals cannot be opened
interchangeably. The shared source registry remains permanent across variants.
There is no automatic journal migration or missing-store recreation.

## Native checks and deadlines

The closed canonical ASCII request contains exactly `mode`, `endpoint`,
`not_before`, `not_after` and the complete `record`. It is at most 65,536 bytes.
The mode is `TN10_P0_SUBMISSION_REQUEST_V0`; timestamps are bounded integer UTC
seconds, with a positive window of at most 30 seconds. Unknown/duplicate fields,
noncanonical encodings, fixture plans, changed signatures, layout or full hash
are rejected before networking.

The controller checks current paired input metadata after constructing its
dispatch payload. It carries forward the earliest expiry of both accepted-chain
samples and positive source/ticket samples. It never grants a new full freshness
window merely because dispatch starts later. A window already exhausted before
connection stops the sender and retains the attempt as uncertain.

The native sender:

1. Revalidates the entire saved P0 record with the shared native verifier.
2. Requires a canonical `wss` TN10 Borsh endpoint. It uses that exact endpoint,
   or an explicit loopback relay whose configured upstream matches it. There is
   no SDK resolver selection or application endpoint fallback.
3. Starts a monotonic timeout bounded by the remaining UTC observation window.
4. Checks the connected server reports `testnet-10`, synchronization, UTXO
   indexing and the pinned covenant activation DAA threshold.
5. Queries the role address and requires the exact input outpoint and complete
   amount/script/creation-DAA/coinbase/covenant metadata. Missing, duplicate,
   changed or future-dated entries fail.
6. Rechecks node health/network and UTC deadline before one
   `submit_transaction(saved_rpc, false)` call. The boolean disables orphan
   admission; the separate replacement API is never called. A backwards native
   clock fails.
7. Accepts only the expected transaction ID as a reported acceptance. Any error,
   timeout or mismatched response is uncertain. Cleanup is bounded and never
   retries a submission.

The deadline limits connection/preflight work as well as the submit call. It
cannot recall bytes already sent or atomically freeze chain state. A node view
can change after its final sample. An RPC timeout leaves possible network effects.
The SDK connection may reconnect internally, but the application makes no second
submit call; its Borsh request path posts one request and tracks its reply.

## Process handling

The Python transport invokes the pinned relay/native sender with the canonical
request on stdin. It passes only PATH/proxy settings and the pinned upstream,
excluding inherited signing keys and RPC overrides. It incrementally writes
bounded input and reads at most 4,096 stdout bytes; stderr is discarded. Its
40-second outer timeout kills the whole relay/native process group on failure.
The native window remains the tighter dispatch limit.

The relay uses the existing TLS WebSocket implementation and configured proxy
environment. Pinning a configured URL/build is not server attestation, proof
of operator independence, a hostile-host execution boundary or a certificate
key pin. Native RPC frame decoding happens before the UTXO result-count limit;
upstream decoder memory/resource isolation remains separate work.

## Trusted harness sequence

```sh
cargo build --locked --features live --example ticket_read --example ticket_pilot_review --example ticket_pilot_private --example ticket_pilot_submit
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_ticket_pilot_live.py' -v
```

Construct `ticket_pilot_live.Transport(first_tracker.endpoint)` and the distinct
`Controller(..., observations=pair, transport=transport)`. The first configured
tracker must match the sender endpoint exactly. Call `recover()`, refresh both
observers and explicitly reconcile their current handles before preparation or
submission. Keep observer databases outside private backup directories.

After saving an issue outbox, `submit('issue')` reserves once and invokes the
adapter. A second call is always refused, including after reported rejection or
a failure before any send. Refresh observers and call `reconcile_submission`
to obtain a revocable current observation. Never infer confirmation from a
transport reply. Accepted issuance and current ticket metadata permit one
permanent consume/refund choice and terminal preparation/submission.

Status reports `network_submission_capable=true`, historical attempts and
normalized replies. It gives no fabricated zero-broadcast count or permanent
confirmation flag, signed RPC or private key. `submit_simulated` is rejected by
the live policy. The standalone native CLI can bypass the journal; callers with
keys, local code or transport access remain outside this trusted policy boundary.

## Evidence and remaining work

Eight new Rust tests cover endpoint/route/window and exact UTXO gates. Twenty-seven
new Python tests exercise the live policy, shared native verifier, expired/future
requests that stop before connection, pipe limits/environment/termination,
timeouts, branch/source continuity and read-only reconciliation. Controller
transport replies and chain observations in these tests are simulated; native
`verify` replies explicitly say `VALID_NOT_SENT`.

No operational keys, funding request, successful network handshake/submit,
actual data-key delivery or P0 chain acceptance was produced here. Before live
acceptance, verify fresh role-key backups/possession, then run independent
funded consumption and unused-refund pilots with separate journals/nonces/sources.
Retain exact outboxes and reconcile every failed or unknown attempt. The default
five-second window may expire on slow endpoints; availability/fee adequacy must
be measured without silently widening a pinned policy or retrying an intent.

The host, code, clock, registry, independent checkpoint authority and node views
remain trusted. Jointly restoring all trusted stores can erase an attempt;
post-sample reorgs remain possible. No global exactly-once, independent signer,
grant/recipient authorization, quota enforcement, quantum safety or audit claim
is added. [Verification record](../evidence/ticket-pilot-live-verification.md).
