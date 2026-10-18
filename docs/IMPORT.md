# Public repository import - October 18, 2026

Public home: https://github.com/GEEKProtocol0110/icp-kaspa

This repository imports the prepared vault/watchtower source and public test
evidence at pre-publication commit
`61f40a9f57d9b2f39160fabcf276d505b1278c19`, followed by publication documentation
and license updates. No custody or controller behavior was changed for import.

The initial GitHub commits use GitHub's connected Git-data API, so their commit
IDs differ from the local development history. The complete original history
is preserved in `history/pre-github.bundle`, including the baseline vault
commit and `milestone/watchtower-testnet` tag. From this repository's root:

```bash
git bundle verify docs/history/pre-github.bundle
git clone docs/history/pre-github.bundle ../icp-pre-github-history
```

The bundle is an immutable historical record. Its earlier publication and
licensing checkpoints are superseded by the current README, NOTICE and LICENSE.
It contains source and public evidence, not funded-session keys or runtime
databases. Continue development on this repository's main branch.
