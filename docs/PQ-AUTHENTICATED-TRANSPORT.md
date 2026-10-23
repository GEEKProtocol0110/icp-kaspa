# Authenticated transport for experimental PQ envelopes

`scripts/pq_authenticated_transport.py` adds a separately pinned, mutually
authenticated TLS 1.3 connection around the existing encrypted message. The
sender uploads and the recipient downloads using distinct TLS certificates.
The relay holds one immutable opaque envelope in memory and has no PQ endpoint
key, decryption operation, public bind or filesystem-serving route.

This is a loopback experiment on one trusted POSIX host. TLS uses conventional
certificates; key-exchange groups follow the linked OpenSSL backend's defaults
and are not separately pinned or asserted here. This supplies **no post-quantum
TLS authentication guarantee**. The inner [PQ message profile](POST-QUANTUM-RECIPIENT-PROFILE.md)
retains its library hybrid ML-KEM-768/X25519 encryption and ML-DSA-65 signatures.
No Kaspa native signature, custody rule, funded session or chain-release rule
changes. This milestone is not independent-device isolation or an audit.

## Identity and transport boundaries

| Boundary | Implemented behavior |
| --- | --- |
| Trust roots | Explicit CA file only; no implicit system roots |
| Relay identity | Verified certificate chain and DNS/IP hostname, then exact SHA-384 DER certificate pin before sending HTTP bytes |
| Client identity | Required client certificate chain and TLS client-purpose validation; exact upload/download certificate pins authorize the operation |
| Role separation | Different TLS certificates required; upload credential cannot download and download credential cannot upload |
| Protocol | TLS 1.3 only, HTTP/1.1 ALPN, session tickets disabled, no HTTP fallback, proxy lookup or redirect following |
| Secret input | Hidden prompt or bounded owner-only file/pipe FD, inherited from the locked adapter; no password argument/environment option |
| TLS key files | Bounded owner-only regular encrypted PKCS8 PEM; library decrypts during context setup; no plaintext PEM publication |
| Payload | One immutable object, 1..196,608 opaque bytes, SHA-384 content address; duplicate exact upload is idempotent |
| HTTP framing | One decimal Content-Length; Transfer-Encoding and duplicate lengths rejected; bounded response reads and checksum verification |
| Socket behavior | Three-second per-socket timeout, single request per connection, loopback ephemeral bind |
| Output | Download publication is private, atomic and no-clobber using the existing adapter writer |

CA trust, certificate pins and PQ policy pins are separate inputs. They require
authenticated out-of-band distribution. A certificate does not establish a
person's real-world identity or bind itself to a PQ role key. Pinning the exact
certificate means renewal needs an explicitly trusted pin change; no automatic
rotation, trust-on-first-use, enrollment, revocation/CRL/OCSP service or recovery
procedure is supplied. The trusted host can alter this configuration.

TLS authentication precedes application delivery. The server receives the
client certificate during the TLS handshake, before the client checks the
additional exact server pin. A wrong server pin prevents HTTP request/body
transmission; it does not conceal the client's TLS certificate from that peer.
The relay can observe sizes, timing, client certificates and encrypted envelope
metadata. TLS does not hide traffic patterns from the relay or network observers.

## Reproduce the fictional exchange

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_pq_authenticated_transport.py' -v
python3 examples/pq_authenticated_file_exchange.py
python3 scripts/pq_authenticated_transport.py --help
```

The demo generates a temporary fictional ECDSA test CA in memory and short-lived
server/upload/download certificates. It writes only encrypted private PEM files.
The CA is a test fixture, not a production identity service. The trusted parent
process generates all role material and therefore supplies no host isolation.
Seventeen existing encrypted-endpoint CLI operations, two new TLS client
processes and one separate TLS relay process exchange the fictional binary.
They verify exact recipient bytes, the signed receipt, replay rejection, checked
encrypted-key backup and saved receipt recovery. No plaintext or secrets are
included in the [saved flags](../evidence/pq-authenticated-transport-demo.json).

The CLI requires explicit `--ca`, `--certificate`, `--key`, then `serve`, `put`
or `get`. `serve` requires separately trusted `--upload-pin` and `--download-pin`.
Clients require `--host`, `--port` and `--server-pin`; `put` reads `--input`,
while `get` requires `--object-id` and a fresh `--output` path. Global
`--passphrase-fd` precedes the subcommand. Password FD rules are documented in
the [encrypted-keystore guide](PQ-ENCRYPTED-KEYSTORE.md). TLS keys are distinct
from message signing/delivery keys; their encrypted PEM uses the cryptography
library's `BestAvailableEncryption`, not the endpoint JSON keystore format.

## Limits and next work

The standard-library single-threaded HTTP server is a local fixture. Socket
timeouts are not total request deadlines; slow clients can monopolize it.
There is no production admission control, rate limiting, high availability,
streaming, durable mailbox, independent storage service or public deployment.
A relay restart loses its object. A successful upload is not recipient acceptance;
only the existing verified signed receipt is the recipient's authenticated
claim. An idempotent upload cannot reaccept a message into an intact recipient
store, and it supplies no globally unique delivery guarantee.

Static delivery-key compromise still exposes earlier messages. Compromised
unlocked hosts, weak passphrases, copied/rolled-back replay stores and separate
receipt/plaintext export remain limitations of the inner experiment. There is
no hardware isolation, memory zeroization, quantum-hardware test or FIPS
certification. Production PKI, authenticated role enrollment/rotation, transport
hardening, independent-device trials and independent protocol review remain.

## Primary references

- [Python SSL contexts and certificate validation](https://docs.python.org/3/library/ssl.html)
- [Python HTTPSConnection](https://docs.python.org/3/library/http.client.html#http.client.HTTPSConnection)
- [Python HTTP server limitations](https://docs.python.org/3/library/http.server.html)
- [cryptography 50.0.2 X.509 APIs](https://cryptography.io/en/50.0.2/x509/reference/)
