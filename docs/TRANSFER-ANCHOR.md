# Transfer commitment observer v0

`scripts/transfer_anchor.py` adds a read-only Kaspa Testnet-10 observation layer
alongside the [local transfer lab](TRANSFER-LAB.md). It can match a pinned
transaction ID and exact payload in native accepted-chain scan responses,
track selected-chain successors and undo observations after a reorganization.
The original milestone used synthetic offline evidence. A later
[journaled TN10 run](ICP-Transfer-Anchor-Live-Proof.md) submitted one anchor and
observed it through two distinct endpoints, including its exact self-return
output. That dated observation does not provide a consensus or finality proof.

The observer does not change the receiver's acceptance rules. It does not sign
or broadcast, deliver keys, consume read tickets, enforce release accounting or
prove remote decryption. Custody contracts and funded sessions are unchanged.

## Commitment format

The complete signed encrypted envelope and pinned policy are first validated
using `verify_envelope` at the manifest's claimed issue time. This permits
historical inspection; observation status separately checks current expiry.
The commitment body is exactly:

```json
{
  "version": "icp-transfer-anchor-v0",
  "network": "testnet-10",
  "policy": "the complete Policy.body() object",
  "envelope": "the complete signed envelope object"
}
```

The last two strings above describe objects, not literal wire values. Use the
existing canonical JSON encoding: sorted keys, compact separators, ASCII,
no NaN. Compute SHA-256 over the ASCII domain `icp/lab/anchor/v0`, one zero
byte, then the canonical body. The proposed transaction payload is the ASCII
prefix `ICP-XFER-TN10-V0`, one zero byte, then the raw 32-byte digest: 49 bytes
total. Native RPC represents those bytes as lowercase hex.

This binds the policy, manifest, ciphertext and both authorization signatures.
The later recipient receipt is not included. This is a pre-receipt transfer
commitment, not proof that anything was delivered or executed. The payload
exposes a commitment and its chain timing; publishing matching envelopes later
can make transfers linkable. No plaintext or symmetric key belongs on chain.

An independently trusted operator pins the expected transaction ID and a
bootstrap selected-chain hash **before** the expected accepting block. A matching
payload in any other transaction does not count. The observer trusts the node's
transaction ID and payload association; it does not recompute transaction IDs,
verify Merkle/SPV proofs, headers, PoW or consensus. It also does not constrain
the anchoring transaction's inputs, outputs, fees or funding authority.

## Observation rules

Consume the existing native `icp scan HASH` envelope: guarded TN10 node info,
`from` cursor, sampled sink `target`, and VSPC v2 changes at Full verbosity with
RPC minimum confirmations set to zero. Only `acceptedTransactions` under a
reported selected-chain accepting block can establish the match. A broadcast
result, mempool entry, or transaction in an arbitrary block is insufficient.

Apply each page atomically to a separate SQLite database. Removals must undo
the exact current tip in order. Additions must match the complete ordered header
list; an active block cannot appear twice. Duplicate accepted transaction IDs,
a mismatching payload under the pinned ID, malformed/missing required fields,
stale cursors or a rollback below bootstrap stop processing. A failed page
leaves the prior durable cursor/history intact and disables usable status.
Reconcile node/history problems before retrying; do not discard the database
to manufacture an observation.

Count the selected-chain entries **after the accepting block**. The accepting
block contributes zero successors. This is a local observation threshold,
separate from the node RPC's blue-score confirmation option. DAA delta,
parallel DAG blocks and elapsed seconds do not supply successors. The default
10 successors is an uncalibrated experiment setting, not a risk estimate,
production recommendation or finality guarantee.

The sampled sink must still occur on the tracked branch before status can
qualify. A paged response ending before that target remains `CHAIN_BACKLOG`;
fetch the next page from the committed tip. If a reorg removes the accepting
block, the observation disappears. Reacceptance starts a new successor count.
Removing only successors can also revoke the threshold. Once delivered,
off-chain plaintext or keys cannot be recalled by this rollback.

| State | Meaning |
| --- | --- |
| `SCAN_REQUIRED` | No fresh successful scan in this process, or last attempt failed |
| `STALE` | Local scan age exceeds the configured limit, or its timestamp is in the future |
| `CHAIN_BACKLOG` | Sampled target is absent from the tracked branch |
| `PERMISSION_INACTIVE` | Manifest is not currently active under the trusted local clock |
| `NOT_FOUND` | Pinned transaction/commitment is absent from tracked acceptance history |
| `WAITING_SUCCESSORS` | Match exists but the chosen successor threshold is not reached |
| `OBSERVED_COMMITMENT` | Match, successor threshold, sampled-target catch-up and local freshness checks pass |

`OBSERVED_COMMITMENT` is a revocable report from a trusted source, not an access
authorization, consensus proof, trusted timestamp or globally consumed ticket.
All states include `mode=TRUSTED_NODE_OBSERVATION_ONLY`. The recipient's existing
signed receipt remains an independent local claim.

## Use and verify

Run the reproducible synthetic demo from the repo root:

```bash
python3 scripts/transfer_anchor.py
python3 -m unittest discover -s tests -p 'test_transfer_anchor.py' -v
```

The demo reuses the public signed exchange in
[transfer-lab-demo.json](../evidence/transfer-lab-demo.json), fabricated IDs and
a simulated historical clock. Output is pinned in
[transfer-anchor-demo.json](../evidence/transfer-anchor-demo.json) and labeled
`SYNTHETIC_CHAIN_NO_RPC_NO_FUNDS`. It is not live-chain evidence.

For a future separately journaled live observation, an application imports
`AnchorTracker`, constructs it with the trusted `Policy`, signed envelope,
expected transaction ID and prior bootstrap, and calls
`tracker.scan(Native(), lambda: int(time.time()))` using the repository's
`watchtower.Native` read adapter. Build the native CLI first. This method invokes
only `scan`, invalidates cached status before the RPC and uses fetch-start time
for freshness so RPC latency cannot make an old response appear new. Poll on
one controller per DB, including immediate catch-up while behind. Close the
tracker when finished. No live broadcaster is supplied by this module.

`apply(response, observed_at)` is for tests or adapters with a trusted local
fetch time. Replaying downloaded scan files with the current time **does not**
establish freshness or current chain membership. Reopening a database requires
a new scan before any status can qualify. The DB pins the exchange commitment,
transaction ID, bootstrap, successor threshold and maximum age. Never share
this DB with custody/watchtower or receiver state.

Local limits are 4,096 added blocks, 2,048 removals and 100,000 accepted
transactions per page. Oversized pages fail without partial commits. These
are processing limits, not RPC byte/memory limits. History grows without
automatic pruning; bootstrap/deep-reorg/pruned-node reconciliation remains
manual. The DB, operator pins, native binary, node, clock and adapter are trusted.
There is no SPV, independent-node quorum or secure-time source.

## Pinned upstream basis and next gate

Reviewed at rusty-kaspa revision
`a41a333b08848f41bf737b72592e463a6011b8ac`:

- `rpc/core/src/model/tx.rs` and `model/optional/tx.rs`: hex payload and verbose
  transaction IDs in optional/full transaction representations.
- `rpc/service/src/service.rs::get_virtual_chain_from_block_v2_call`: paged
  selected-chain acceptance responses and optional blue-score filtering.
- `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs`:
  test explicitly permits a nonempty native transaction payload in isolation.
  This alone does not demonstrate submission, mass/fee adequacy or acceptance
  of this proposed anchor on a live node.

The [pilot](TRANSFER-ANCHOR-PILOT.md) now specifies a bounded self-returning
funding transaction and journals submission plus two-endpoint observation.
Its [live evidence](ICP-Transfer-Anchor-Live-Proof.md) is separate from the
synthetic fixtures. Next, define revocation,
release authority and a replay/accounting protocol before connecting any chain
observation to protected key delivery.
