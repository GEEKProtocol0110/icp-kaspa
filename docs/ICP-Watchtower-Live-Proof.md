# ICP watchtower - live testnet proof

**Passed on Kaspa testnet-10, October 18, 2026.**

The actual watchtower preserved a withdrawal explicitly approved before
broadcast and automatically recovered a different unapproved withdrawal. The
approved withdrawal then completed after the delay. Both paths were followed
through accepted-chain transaction data, not just mempool responses.

| Step | Transaction ID |
| --- | --- |
| Deposit | `1808543e2b465c0900a93cf637adb6089fdc5c00abbca13968a91e04b0979319` |
| Approved intent | `f3eb80c6c0713a18da3c2b5253b1577625785267073bcd3ba7151891f91d7f21` |
| Unexpected intent | `5631b2fe49e0d509835eca6a7793e027e5aba0c4db2e5613d0485a8d062bbe30` |
| Automatic recovery | `fc721df0da069607361ec50ea2708a11e59ef7c5e350d9c8a6575f0bf5800bcc` |
| Approved payout | `b7828e6f747a26f3d43f3c27eebe7e903ecc1ff7082923c4a7f1f2359bdecbb4` |

Automatic recovery required **one broadcast attempt**. The unapproved intent
was accepted at DAA 599968344; recovery was accepted at DAA
599968584, a difference of 240 DAA units, within the
600-DAA withdrawal delay. This is an observed run, not a guaranteed SLA.

The approved intent was not treated as an intrusion. The watchtower recorded
its later payout as EXECUTED. No live pending vault output remained at the end.
The test created two 0.30-test-KAS vault outputs; each final payout was 0.26
test KAS after initiation and exit fees. Total remaining across the original
session addresses was 2.80 test KAS after both live milestones.

Local verification: **54 checks passed**: 27 compiled vault-script tests,
3 network guards, and 24 watchtower tests. Watchtower tests cover approval
binding/expiry, replayed scan cursors, incomplete data, node health, reorg undo,
restart reconciliation, bounded retries, and rejected signer redirection.
Real reorgs/outages were not induced on public TN10. CI is prepared but has
not run on GitHub because a hosted repository has not yet been created.

## Durable results and limitations

`evidence/watchtower-live.json` contains the live journal, recovery outbox,
operator policy decisions, final chain state and audit events. The SQLite
database and private keys are in the separate private session backup.

The controller uses a trusted node and a local trusted approval database.
The test signer still shares a host/key file with the owner role. Recovery
currently exits into a conventional fixed P2PK address; a protected recovery
covenant and production signer isolation remain to be built. No permanent
hosted daemon or external alert destination has been installed. This is a
prototype test result, not an external audit or quantum-security proof.
