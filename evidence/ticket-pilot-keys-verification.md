# P0 test-key setup verification — October 22, 2026 UTC

The offline setup generated two new Testnet-10 sessions, one for consume and
one for unused refund. All six independent funding/ticket/return keys passed
curve/public-key checks, saved possession verification, exact-byte archive
restoration and fresh restored-key possession challenges. Public addresses were
derived by the pinned native Kaspa library without fabricating a funding source.

The verified private archive was durably saved before these funding details
were written. Its contents are private and excluded from Git. The
[public receipt](ticket-pilot-key-preparation.json) records the session, archive
and public-manifest digests, binary fingerprint and zero transaction signatures,
RPC calls and broadcasts. Its original setup receipt intentionally retains the
local-only warning; the outer `durable_private_backup_saved` field records the
subsequent completed retention gate. No Library identifiers or private key bytes
are published.

## Concrete next funding step

**Testnet-10 test coins only.** Send one output of exactly **24,000,000 sompi
(0.24 test KAS)** to each funding address below. Total requested funding is
0.48 test KAS, excluding the funding sender's fees. Do not send mainnet KAS or
fund the public fixtures, ticket keys or return keys directly.

| Independent pilot | Funding address | One source output |
| --- | --- | --- |
| Consume | `kaspatest:qqneljs6jvhgwxlwja6nysl237x0a675h6p5flf0lu03tjhkqfcfw8te2h3hk` | 24,000,000 sompi |
| Unused refund | `kaspatest:qqqew97ku8t28r3d73nfqt72t7x4weptgsuz78ucz47u05rwapz57m99asxns` | 24,000,000 sompi |

No funding was performed during setup and no source outpoint has been observed.
After funding, inspect and pin the actual transaction ID, index, amount and full
entry metadata through both TN10 observers. Build separate operator reviews
from those actual sources and the backed-up roles/nonces. Each issue/terminal
pair has a 4,000,000-sompi fee ceiling; the two lifecycles together have an
8,000,000-sompi ceiling, excluding initial funding fees.

Use the [live controller](../docs/TICKET-PILOT-LIVE.md) with new, separately
stored journals/authorities/claims/observers. Preserve signed outboxes before
submission intents. Any failed or unknown submission must reconcile read-only;
never blindly repeat it. These addresses are setup outputs, not evidence of
live P0 acceptance or actual data authorization.

## Verification and limits

- `cargo fmt --check` and the locked live-feature Rust suite: 136 tests.
- All five native reviewer/reader/private/submission workers built before Python
  verification; the original unsigned public-fixture demo remains unchanged.
- Python unittest discovery: 677 tests, including twelve new key-setup tests.
- New native tests compare public address derivation with the existing review
  and reject fixture keys, aliases, invalid keys and noncanonical/extra inputs.
- Backup tests cover corruption, digest mismatch, missing/duplicate/traversal
  entries, unsafe permissions/links, wrong/swapped keys and changed context.
  Partial failures return no ready receipt and never overwrite existing files.
- Source checksums, repository-relative documentation links and privacy/secret
  exclusion were checked before publication. CI verifies the final PR head.

All key roles and the unencrypted test archive share a trusted host. The
possession suite uses conventional secp256k1 ECDSA/SHA256; native transaction
signing remains Schnorr in the separate preparer. These checks prove local key
access and restoration, not real-world identity, permission, signer isolation,
current live journal history, independent custody or post-quantum security.
No funding, P0 transaction signing/submission, live acceptance or data-key
release was added by this setup run.
