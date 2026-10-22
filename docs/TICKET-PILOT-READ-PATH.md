# P0 live read path

The first funded preflight verified both 0.24 test KAS sources, then stopped
before signing. Separate process connections aged the samples, one starting
tip moved off the selected chain, and older history reads failed. All three
preflight profiles were retained and halted with zero source claims, signing
intents, outboxes and submission intents. No pilot fee was spent.

The P0 observer now uses a distinct, pinned `TN10_P0_READ_SNAPSHOT_V1` profile.
One bounded native connection performs one two-address UTXO query, followed by
the accepted-history query. Both role samples share the actual node-tip hashes
read before and after that UTXO query. Python timestamps every part with the
caller's request-start time; receipt and decoding do not refresh sample age.
The original LAB0 reader and projection profiles remain separate.

## Native request and checks

`ticket_read observe-p0` reads a closed canonical ASCII object on stdin, at most
1,024 bytes, containing `cursor`, `funding_key` and `ticket_key`. Keys must be
distinct valid lowercase x-only public keys. No private-key field, signer,
funding operation or submission API exists in this command.

The node must report synchronized/indexed Testnet-10 beyond covenant activation
before the query and again after the history read. UTXO rows are split only by
their explicit queried addresses; unexpected or missing address tags fail.
The native connection/read sequence has one 25-second deadline and at most
two additional seconds for disconnect. Serialized output is capped at
32,000,000 bytes. Upstream frame decoding and in-memory values precede that
output cap; this is not hostile-node memory isolation.

The returned `source`, `ticket` and `scan` records must agree on node identity
and actual query brackets. Python rejects mixed roles, cursors, profiles or
targets before updating the tracker. Existing checks still require complete
native bodies, exact positive entries, current branch brackets, required
successors and fresh two-node agreement. A removed bracket remains ineligible.

The pinned node implementation limits history pages by block/acceptance batch
size. The target therefore remains the separately sampled node hash. **The last
returned block is never relabeled as the target.** A partial page can advance
the read-only cursor while reporting `CHAIN_BACKLOG`; further reads must reach
the sampled target. No signing or sending is allowed during backlog.

The WebSocket relay now retrieves failures from both directions, cancels the
opposite direction, and closes both peers with a static failure reason and a
bounded close wait. An upstream failure cannot silently leave its counterpart
waiting. Its existing 8 MiB upstream frame cap is unchanged. Large history,
resource limits, node failures and expired samples can still stop observation;
the implementation does not promise every historical gap is recoverable with
one bounded request.

## Choose a bootstrap before creating a policy

```sh
python3 scripts/ticket_pilot_observer.py bootstrap TN10_WSS_ENDPOINT
```

The command walks twenty selected-parent edges from a sampled node sink and
requires the resulting candidate to be reported on the selected chain. It
rejects missing metadata, repeated parents and mismatched hashes. It creates no
observer database or private journal. This is a trusted-node candidate, not
finality or an independent consensus proof. A later reorg across that bootstrap
still halts the observer; never silently reset it under an existing policy.

Use the candidate with the existing `observe` CLI or trusted P0 harness. Keep
the complete public review, bootstrap, node endpoints, binary/relay hashes,
freshness and successor settings pinned. The read profile participates in the
policy identity, so older databases and private policies cannot be silently
reopened with the new reader.

The live read-only probe used ten required successors, thirty-second observer
age and the already selected thirty-second binding freshness policy. The two
node calls took about fourteen seconds together. The five-second binding default
was not widened under an existing policy. Use a newly reviewed policy when
availability measurements require different supported settings.

## Evidence and remaining work

The [live read-only record](../evidence/ticket-pilot-read-path-live.json) shows
both nodes reporting the exact consume-run funding source as unspent under the
new reader, without a signature, source claim or submission. Regression tests
cover request encoding, role/address routing, mixed snapshots, aged replies,
partial pages, removed brackets, policy pinning and relay failure/cancellation.

The funded consume/refund lifecycles and actual data authorization/key delivery
remain separate acceptance steps. Node, host, code, clock and store trust remain;
a chain change after the last sample can still precede an effect. No global
atomicity, independent signer isolation or post-quantum security is claimed.
