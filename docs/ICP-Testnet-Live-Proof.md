# ICP vault - live testnet proof

**Result: the first vault lifecycle passed on Kaspa testnet-10 on October 18, 2026.**

The node accepted a deposit, two withdrawal intents, recovery and delayed
payout. It rejected the early payout for sequence locks. The final recipient
and recovery outputs were also observed through a second node.

## Transaction evidence

| Action | Observed result | Transaction ID |
| --- | --- | --- |
| Deposit into two vault outputs | Accepted; output observed | `6fad9be014203572f73694084411c90e6ca509744ab46a9bb0b8953b3175535e` |
| Withdrawal intent A | Accepted; output observed | `3dbd6ceca353657fb557c4f1aabe0970115d7699916bdca608ab940e17e77a7a` |
| Early payout attempt | Rejected: sequence lock | `c6cade7b912ae57f9df3d9ab4bfa9ff0d9be8535459670be4f0f4f28810aa328` |
| Withdrawal intent B | Accepted; output observed | `de6ff1f6c59fcf5bf1e08d4333def1452b717177bca1b1f30e3ab274ad9d5939` |
| Recovery payout | Accepted; output observed | `dc7f9a6643e7087014d571d8b3235e02f2af83e27c9b343cd2783d2954c4833d` |
| Payout after delay | Accepted; output observed | `c6cade7b912ae57f9df3d9ab4bfa9ff0d9be8535459670be4f0f4f28810aa328` |

The early attempt and the later successful payout have the **same transaction
ID**. The node first rejected it with: "one of the transaction sequence locks
conditions was not met". After the pending output matured, it accepted it.

Initial funding transaction: `acf8ef9f04c13e8188115574ea933eef8ddc8d1990ddd3785850c4a3270beaa2`.

## Final test balances

| Destination | Amount |
| --- | ---: |
| Fixed recipient | 0.96 test KAS |
| Fixed recovery address | 0.96 test KAS |
| Funding-address change | 0.98 test KAS |
| Total remaining | 2.90 test KAS |
| Total fees across five accepted transactions | 0.10 test KAS |

Second-node observation: synced TN10 node, server 2.1.0, virtual DAA
599951625. The recovery output's DAA score was
599950831; the recipient output's DAA score was 599951362. These are DAA-score
observations, not a count of confirmations or a guarantee against reorganization.

## Fee correction discovered live

The first deposit was rejected because the original 100000-sompi fee was below
the node's 1147200-sompi requirement for compute mass 11472. No vault output
was accepted from that attempt. The funding UTXO was rechecked as unspent.
The runner fee and immutable vault fee cap were raised to 2000000 sompi
(0.02 test KAS) and both vault states were recompiled before depositing.
The full native suite still passed: 27 script tests plus 3 network guard tests.

## Scope and remaining work

This demonstrates this prototype's fixed-destination, two-stage withdrawal and
separately signed recovery paths on the live test network. It is not a security
audit, mainnet-readiness finding, or proof of quantum safety. Recovery currently
pays a conventional P2PK address; all test keys share one host. Local adversarial
script tests are distinct from the live acceptance paths exercised here.

Watchtower automation, protected recovery covenants, key separation and rotation,
external review, and the paper's data-release and proof machinery remain ahead.
No GitHub repository has been created.

Machine-readable evidence is in `evidence/live-pilot.json`,
`evidence/second-node.json`, and the per-transaction JSON receipts inside the
updated source package. Live private keys are only in the separate private
session backup.
