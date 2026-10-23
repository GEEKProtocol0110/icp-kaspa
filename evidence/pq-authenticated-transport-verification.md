# PQ envelope transport verification — October 23, 2026 UTC

## Scope

The [authenticated transport](../docs/PQ-AUTHENTICATED-TRANSPORT.md) wraps the
existing PQ envelope with separately pinned classical TLS 1.3 mutual certificate
authentication. The relay accepts only the upload certificate for PUT and the
download certificate for GET. It binds loopback only, stores one opaque object
in RAM and has no message decryption key. Fresh TLS private PEM files are
encrypted before publication. No native transaction, custody rule, funded
journal, pinned worker or PQ wire format changed.

## Local verification

| Check | Result |
| --- | --- |
| New transport suite | 32 real-handshake/adversarial tests passed |
| Existing PQ recipient and locked endpoint suites | 90 tests passed |
| Conventional recipient suites | 71 tests passed |
| Full authenticated fictional demo | Passed: 17 endpoint CLI operations, two TLS clients, one separate relay process |
| Existing locked demo | Passed with its original HTTP handoff |
| Rust and full native-dependent suite | Required in CI; local cargo/native workers unavailable |
| Whitespace and checksum manifest | Verified before publication |

Inventory: 1,002 tests (142 Rust + 860 Python). The
[required workflow](../.github/workflows/verify.yml) builds native workers and
runs formatting, locked Rust tests, the entire Python suite and all demos,
including the new authenticated exchange. Consult the milestone PR for its
exact-head CI result; targeted local passes do not replace that run.

## Checked boundaries

- Actual TLS handshakes exchange exact binary bytes, including the full
  196,608-byte wire bound. Duplicate exact uploads succeed without replacement;
  a different object cannot replace the stored object.
- Correct CA alone is insufficient: unpinned clients and swapped upload/download
  roles fail. Untrusted client/server CAs, missing/expired client certificates,
  expired relay certificates, wrong certificate purpose, hostname mismatch,
  TLS 1.2, cleartext HTTP and missing HTTP/1.1 ALPN reject.
- A relay certificate pin mismatch is checked before the first HTTP request;
  the test handler observes no upload request and no stored payload.
- Tampered content addresses, missing/duplicate/bad/oversize Content-Length,
  Transfer-Encoding, unexpected GET bodies, unknown/path-traversal routes,
  response truncation, wrong response bytes and redirects fail closed.
- Empty/oversize uploads reject before connection. Oversize declared responses
  reject before reading the body. No environment proxy or SSLKEYLOGFILE logging
  is enabled. Wrong TLS-key passwords, plaintext PEM and unsafe key permissions
  reject. Relaxed server TLS configurations and equal role pins reject.
- The full fictional demo retains exact recipient bytes, signed receipt
  verification, replay rejection after unlock, receipt recovery and checked
  encrypted-key backup through the new transport. The relay gets TLS keys only,
  not recipient message-decryption keys or endpoint passphrases.

The [saved result](pq-authenticated-transport-demo.json) contains flags and
counts, not certificates, passwords, plaintext, private paths or transactions.
It is reproducible local evidence, not a public proof of reading or execution.

## Reproduction and exclusions

```bash
python3 -m unittest discover -s tests -p 'test_pq*.py' -v
python3 -m unittest discover -s tests -p 'test_recipient*.py' -v
python3 examples/pq_authenticated_file_exchange.py
python3 examples/pq_locked_file_exchange.py
```

All participants share one trusted host. Conventional TLS is not post-quantum
TLS; certificate pins do not supply real-world identity, automated PKI,
revocation/rotation or a cryptographic binding to PQ role keys. The local HTTP
fixture is not a public service: per-socket timeouts are not total deadlines,
and a slow peer can deny availability. Metadata remains visible to the relay.
There is no durable mailbox, hardware key protection, hostile-host security,
global anti-replay, chain-gated release or independent security audit. The
recipient experiment's static-key and non-atomic export limits still apply.
