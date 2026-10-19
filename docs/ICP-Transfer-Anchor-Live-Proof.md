# Transfer anchor: funded TN10 observation

On October 19, 2026, the journaled transfer pilot submitted one native P2PK
anchor and passed the two-endpoint accepted-chain observation gate. Both
endpoints subsequently reported the exact self-return output as unspent.

| Item | Recorded result |
| --- | --- |
| Network | Kaspa Testnet-10, synced/indexed nodes, server 2.1.0 |
| Transaction | `dce0ddf4ad0e420918c2216a85e2b179650e6a10ac7566cb60d99eee69b585f1` |
| Source | `21f1ebdbe2c33ac60fb694d4c57c96baf73791b7f3c84ffe8b1094d3fa307a37:1` |
| Source / self-return | 24,000,000 / 22,000,000 sompi (0.24 / 0.22 test KAS) |
| Fee | 2,000,000 sompi (0.02 test KAS), one submission attempt |
| Accepting block | `e8f5fa35d339c0898a3202defa5a4cd5817af81d6351a3822056f3de9ad02f97` |
| Selected-chain successors | 29 on vector-10.kaspa.green; 20 on muon-10.kaspa.blue; required 10 |
| Scan fetch-start time | 2026-10-19 05:54:27 UTC (01:54:27 America/Detroit) on both endpoints |
| Final pilot state | `TWO_NODE_ANCHOR_OBSERVED` |

The source was an exact saved test-funding change output, confirmed unspent on
both endpoints before preparation. The native preparer returned value to the
same P2PK key, verified its Schnorr signature with the pinned native VM, and
fsynced the signed transaction before the pilot durably recorded `SUBMITTING`.
The broadcast response was followed by full accepted-transaction scans; it was
not used as confirmation. Subsequent UTXO reads on both endpoints matched the
exact new outpoint, script and amount. No real KAS was used.

The 49-byte payload commits to a fresh synthetic encrypted exchange, complete
policy and both authorization signatures:

```text
4943502d584645522d544e31302d5630006dcb4dafdd2d25b79c41140d435c326ad87ddfa69e9b54cf8a828b0e4c5ca7c2
```

Public evidence: [transfer-anchor-live.json](../evidence/transfer-anchor-live.json).
It includes the signed encrypted exchange and local recipient attestation,
prepared transaction, checked binary provenance, node observations, ordered
chain-hash traces, matching accepted transactions and later UTXO observations.
Unrelated transactions/nonessential header fields are omitted and the projection
is labeled explicitly. Hashes identify the full raw scan copies retained with
the private operational journal; they are integrity references, not SPV proofs.

The binaries were built and tested by GitHub workflow run `39206538539`, source
commit `b1f08d7adb4fa6213bb7f2ddc7b91579bf69f1c6`. The downloaded artifact and both
binary SHA-256 checksums were verified before use. That pre-live checkpoint
passed 220 checks (68 Rust, 152 Python). A later offline check also binds the
published projection to the exchange/receipt signatures, commitment, output
and successor trace: the resulting suite contains 221 checks (68 Rust, 153 Python).

## Limits

These are dated observations from two distinct TLS endpoints, not a consensus
proof, secure timestamp or guarantee of independent operator ownership. The
successor threshold is an uncalibrated experiment setting; no finality or
latency guarantee follows. No live reorg was induced. Reorg handling was tested
offline; a later reorg can withdraw the observation and cannot recall secrets.

The recipient's receipt was produced by the local experiment before anchoring.
It is not chain-triggered key release or proof of remote execution. Funding
used an ordinary P2PK key on the test host; no independent-host key isolation,
read-ticket consumption, global release limit, quantum-safety or audit result
is demonstrated. Custody contracts and completed custody-pilot journals were
not modified. See [the pilot runbook](TRANSFER-ANCHOR-PILOT.md) for exact failure
and reconciliation rules.
