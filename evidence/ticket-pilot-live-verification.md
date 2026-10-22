# P0 native submission adapter verification

The new live controller connects permanent submission intents/outboxes to a
TN10-only native sender under a distinct policy. Simulation journals remain
simulation-only and cannot be silently reopened as live journals.

The sender reuses the existing native private-record verifier, rejects public
fixtures and altered signature/layout/full-hash data, pins its configured TLS
endpoint, checks the connected node and exact current input metadata, and carries
the original paired-observation expiry through connection and submission. There
is one ordinary submit call with orphan admission disabled, no replacement API
and no retry command.

Eight new Rust tests cover endpoint/relay restrictions, clock windows and all
input metadata fields. Twenty-seven new Python tests cover actual offline native
verification for issue/consume/refund, cross-policy rejection, source/branch and
recovery continuity, unknown replies, deadline preservation, static failures
before connection, environment stripping and real bounded pipe failure/timeout
handling. The full inventory is 799 tests: 134 Rust and 665 Python.

Validation requires formatting, full locked Rust/Python suites, both contract
compilers, unchanged public-review output, existing native demos, relative
documentation links, source digests and privacy checks. Final-head push/PR CI
must pass before merge. Build all native examples before starting Python tests;
fingerprint checks intentionally reject replacing a binary while it is in use.

Evidence is offline/simulated. Native request inspection performs no network
effect; expired/future/misrouted submit requests are tested only where they fail
before connection. There was no successful P0 RPC handshake/submission, funded
P0 run, operational key generation, funding request or data-key delivery.

Trust limits include endpoint/node/code/clock/store trust, configured URL rather
than server attestation, decoding before native result-count checks, raw-worker
and raw-sender bypass, post-sample chain changes and joint trusted-store restore.
Successful transport replies are not chain confirmations. See
[the guide](../docs/TICKET-PILOT-LIVE.md) for API sequencing and live acceptance gates.
