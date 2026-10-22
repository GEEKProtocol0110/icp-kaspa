# Fresh P0 test-key setup

This offline helper prepares two separate Testnet-10 sessions: one for consume,
one for unused refund. Each has independent funding, ticket and return roles.
It creates no transaction, funding source, observer journal or network request.

## Create and preserve a backup

Build the native public reviewer, install `requirements-lab.txt`, then run:

```sh
cargo build --locked --features live --example ticket_pilot_review
umask 077
python3 scripts/ticket_pilot_keys.py create /private/new-p0-session /private/new-p0-backup.zip
```

Use new absolute paths on a trusted host. Failure leaves partial files for
inspection; never reuse them automatically or fund an incomplete session.
Existing directories and archives are never overwritten. Keys are raw lowercase
64-character hex files, compatible with the private preparer. Directories use
0700 and files 0600; symlinks, hard-linked files and unsafe permissions fail.
The helper rejects symlink ancestors. It does not isolate roles on separate
machines, encrypt the archive, erase process memory or establish hardware custody.
The archive contains all six **test-only private keys**; keep it confidential.

The native reviewer's separate `addresses` command accepts only a canonical,
closed map of `funding_key`, `ticket_key` and `return_key` public x-only keys.
It derives addresses with the pinned Kaspa library, rejects aliases and known
fixture keys, and needs no fabricated source or unsigned transaction. The
address prefix identifies a test network; the session manifest pins Testnet-10.

Setup verifies six distinct curve keys and distinct nonces. For each role it
signs a domain-separated ECDSA/SHA256 possession challenge that binds network,
session, branch, nonce, role, public key and address. These are **possession
proofs, not Kaspa Schnorr transaction signatures or authorization**. Only public
keys reach the native address subprocess; inherited credentials are excluded.
The binary fingerprint is checked before every invocation.

Before returning a receipt, setup verifies the closed archive, restores it into
a new temporary private directory, checks exact bytes and permissions, derives
the public addresses again and signs fresh possession challenges with all six
restored keys. Archive loading checks an externally supplied SHA256, exact entry
names, duplicate entries, bounded lengths and uncompressed format. No ZIP paths
are extracted directly. A digest provides integrity relative to a trusted copy,
not independent authentication against an attacker replacing both copies.

The public receipt deliberately says `LOCAL_ONLY_MUST_PERSIST_BEFORE_FUNDING_REQUEST`.
Save the verified archive in durable private storage and retain its digest
separately **before publishing a funding request**. A local scratch file alone
does not complete that gate. This is a pre-funding key backup, not a live-state
recovery snapshot. Later checkpoint authorities, source claims, observers and
signed outboxes have their own separation and rollback requirements.

To restore later, build the current public address helper and use a trusted
archive digest from the setup receipt:

```sh
umask 077
python3 scripts/ticket_pilot_keys.py restore /private/new-p0-backup.zip /private/restored-p0-session EXPECTED_SHA256
```

All checks apply again. A successful restore proves access to those test keys;
it does not prove that live journals are current or permit repeating a send.

## Funding and acceptance remain separate

After the backup gate, obtain **one 24,000,000-sompi (0.24 test KAS) output** to
each session's funding address on **Testnet-10 only**. This is 0.48 test KAS total;
funding fees are separate. The issue/terminal pair costs 4,000,000 sompi per run,
within the combined 8,000,000-sompi pilot lifecycle fee ceiling. Do not fund the
ticket/return roles directly, combine both branches in one session, or use public
fixture addresses. No mainnet funds belong in these sessions.

Once exact funding outpoints exist, build fresh operator plans with their actual
source IDs/indexes/amounts and the saved public roles/nonces. Pin the complete
review, evidence digest and current binary hashes. Inspect source entries and
activation through both current nodes before using the
[bound private preparation](TICKET-PILOT-BINDING.md) and
[live submission journal](TICKET-PILOT-LIVE.md). Funding alone does not authorize
a signature or submit. Unknown outcomes reconcile read-only; never retry a send.

Funded P0 acceptance and actual data authorization/key delivery remain pending.
Conventional secp256k1 possession checks add no post-quantum claim.
