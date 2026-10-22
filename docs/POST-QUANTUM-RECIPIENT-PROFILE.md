# Experimental post-quantum recipient profile

This separate ICP message-layer experiment encrypts fictional bytes for a pinned
recipient using hybrid ML-KEM-768/X25519 HPKE. ML-DSA-65 signs approvals,
sender manifests, possession proofs, binding certificates and recipient receipts.
It changes no Kaspa consensus rule, wallet transaction signature, custody
contract, funded pilot or reviewed R0 delivery suite. It is not a claim that
Kaspa, ICP or connected applications are quantum-proof or independently audited.

The optional [encrypted software keystore](PQ-ENCRYPTED-KEYSTORE.md) now
protects fresh endpoint keys at rest and verifies encrypted key backups without
changing this wire profile. The original adapter retains its ordinary TEST
key files. Neither option supplies hardware isolation or global anti-rollback.

## Fixed profile and trust boundary

| Component | Exact choice |
| --- | --- |
| Implementation | Pinned `cryptography==50.0.2` from `requirements-lab.txt` |
| HPKE suite | Library `MLKEM768_X25519`, `HKDF_SHA256`, `AES_256_GCM`, base mode |
| Authorization and acknowledgment | Library ML-DSA-65, full canonical JSON message, purpose-specific signing context |
| Commitments and policy pin | SHA-384, domain-separated identifiers; pin is 96 lowercase hexadecimal characters |
| Namespace | `icp-pq-recipient-experiment-v0` |
| Mode | `LOCAL_PQ_RECIPIENT_EXPERIMENT_NO_CHAIN`, labeled Testnet-10; no RPC |
| Plaintext | 1 through 65,536 bytes; no streaming or chunking format |
| Serialized envelope cap | 196,608 bytes, accounting for larger public keys and signatures |
| Default lifetime | 300 seconds, trusted local clock; policy maximum 3,600 seconds |

The library implements the hybrid KEM; this project does not combine shared
secrets itself. Both the ML-KEM and X25519 components belong to the recipient.
HPKE base mode supplies encryption; the separate ML-DSA signatures authenticate
the roles. There is no algorithm negotiation, classical fallback or automatic
migration. An unsupported backend fails closed. The old recipient adapter
retains its existing conventional suite and namespace.

Public signing keys are 1,952 bytes and signatures are 3,309 bytes. The delivery
public record is the 1,184-byte ML-KEM public key followed by the 32-byte X25519
public key. Private test storage contains a 32-byte ML-DSA seed and, for the
recipient only, the 64-byte ML-KEM seed followed by the 32-byte X25519 key.
This is an explicit experimental local storage format, not a general key import
standard. No private key appears in public records, envelopes or example output.

The policy pins three distinct signing roles, the delivery key, epoch, limits,
namespace and suite. Public records and the policy fingerprint require
authenticated out-of-band distribution. An encrypted one-use challenge checks
delivery-key possession; the approver signs the exact binding. That establishes
possession under the trusted policy, not real-world identity or actual consent.

## Reproduce the bounded exchange

```bash
python3 -m pip install --only-binary=:all: -r requirements-lab.txt
python3 -m unittest discover -s tests -p 'test_pq_recipient.py' -v
python3 scripts/pq_recipient_lab.py
python3 examples/pq_recipient_file_exchange.py
python3 scripts/pq_recipient_adapter.py --help
```

`scripts/pq_recipient_adapter.py` exposes the same commands and Python endpoint
methods described in the [file adapter guide](RECIPIENT-FILE-ADAPTER.md), using
new PQ endpoint directories, public records, policy and replay stores. Use that
script in every command, distribute its new 96-character policy pin, and never
reuse conventional keys or relabel an old database. Both profiles reject the
other profile's endpoint records and envelopes. Database policy binding also
rejects direct reuse across profiles.

The example runs 15 endpoint CLI processes and one opaque HTTP relay on
`127.0.0.1`, all on one host. Only the recipient endpoint receives the delivery
private key. A fictional binary file is encrypted, separately approved/signed,
relayed, decrypted and acknowledged. The example also checks replay and wrong
role rejection and exact saved-receipt recovery after process restart.
The relay's SHA-256 URL digest is only an opaque transport checksum; it grants
no authority. Recipient verification uses the pinned PQ profile and signatures.
This example does not test remote delivery, TLS or independent-device isolation.

## Security coverage and remaining work

| Boundary | Implemented or remaining |
| --- | --- |
| Message confidentiality | Hybrid library encryption; fresh encapsulation; recipient-owned delivery keys |
| Role authentication | ML-DSA-65 signatures bound to policy, purpose and exact message |
| Tampering and substitution | Signed metadata and ciphertext commitments plus HPKE context authentication |
| Downgrade | Separate namespace, key formats and policy pin; no conventional fallback |
| Local replay | SQLite receipt commits before returning plaintext; one claim against an intact store |
| Filesystem | Owner-only test endpoints/keys/state, bounded regular-file reads, symlink rejection and atomic no-clobber output |
| Private key protection | Original adapter uses unencrypted TEST files; optional encrypted software adapter available; normal process memory and reviewed device integration remain limits |
| Forward secrecy | Not supplied; compromise of the full static delivery key exposes recorded historical ciphertext |
| Replay after rollback | Copied/restored state can accept again; no global uniqueness guarantee |
| Metadata | Roles, public keys, sizes and timing remain visible; no anonymity claim |
| Chain enforcement | No chain gate, real permission source, wallet change or native post-quantum Kaspa signature |
| Transport and availability | Single-host loopback example only; authenticated remote transport, limits and independent hosts need review |

Receipt persistence and filesystem export are not one atomic operation. Export
failure may leave an accepted claim without a plaintext file. Recover the saved
receipt; do not erase state or repeat acceptance. A signed receipt is the
recipient's local claim, not proof of reading, execution or chain confirmation.
The sender necessarily knows the source plaintext; an authorized recipient can
copy or disclose it. No protocol can promise that only one person ever sees it
after their device or keys are compromised.

The [verification record](../evidence/pq-recipient-verification.md) describes
adversarial checks and the [saved example flags](../evidence/pq-recipient-demo.json).
These are software tests of fictional data, not experiments against a quantum
computer or a security proof. Before sensitive deployment, the next work is
reviewed key storage/recovery, authenticated identity bootstrap and transport,
key rotation/revocation, operational isolation and independent protocol review.
Any native Kaspa signature transition requires separate network-level work.

## Primary references

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [cryptography 50.0.2 HPKE API](https://cryptography.io/en/50.0.2/hazmat/primitives/hpke/)
- [cryptography 50.0.2 ML-DSA API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/mldsa/)

Using algorithms with NIST standards does not certify this implementation,
hybrid profile, cryptographic module or overall application as FIPS compliant.
