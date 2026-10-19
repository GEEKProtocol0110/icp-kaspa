# Delivery-key binding and response-record verification

Date: October 19, 2026.
Mode: `LOCAL_DELIVERY_BINDING_ATTESTATION_SYNTHETIC_NO_CHAIN`.

## Implemented

A separate local lab commits the recipient's actual X25519 public key/epoch into
its signed policy, checks a fresh HPKE-encrypted possession challenge and records
recipient/approver/service signatures in the checkpointed ledger. A service
response record shares the private candidate's vault event and is copied exactly
to the response commit. A client verifier checks the complete non-secret bundle
against its intended signed permission and original admission.

No actual record/content key is encrypted or released. Chain/record facts remain
fixtures and there is no transport or native ticket. Read
[the guide](../docs/BOUND-RESPONSE-LAB.md) for exact formats and assumptions.

## Validation

- 45 new Python tests: 44 bound-response cases and one shared signed-context
  regression. Full local Python suite: 379 tests.
- Full project suite: 447 tests including 68 Rust tests. Required CI also runs
  compiler/format/build checks, seven demos and deployment-template verification.
  Passing final-head CI is required before merge; Rust/native checks run there.
- Public transcript: bound-response-demo.json. It includes public configuration,
  signed evidence and a committed, explicitly non-secret placeholder bundle.
  Tests reconstruct its configuration and verify without private keys.
- An actual child process exits after the vault candidate/record commits but
  before checkpoint acknowledgment. Recovery preserves its exact signature and
  response. The crash-test service key passes only through child stdin; no
  private values are written into public evidence.

| Case | Result |
| --- | --- |
| Identity key alone | Correctly signed/approved fake token hash fails the private expected-hash check without burning the challenge |
| Wrong delivery key / weak key / signing-key reuse | Rejected; an unrelated private key cannot decrypt the HPKE token |
| Modified challenge ciphertext | Invalid service signature or HPKE authentication failure |
| Wrong role, purpose, service/configuration or proof link | Registration/record verification fails |
| Replay, expiry or old generation | No new binding; completed certificate remains exactly recoverable |
| Missing registered binding | Signed grant admission is blocked before claims/charges |
| Ambiguous numeric types | Canonical byte comparisons reject boolean/float substitutions in bundle, service-signed record and stored admission context |
| Changed key configuration | Existing policy-pinned stores cannot reopen; no automatic counter reset/migration |
| Candidate/commit crashes | Certificate/nonces and response/signature records remain atomic in their component events; lost acknowledgments recover exact state |
| Response/context/record substitution | Client verification fails against the intended permission and admission |
| Signature corruption or vault/ledger disagreement | Integrity halt, without re-signing |
| Retries/restart | Identical complete bundle and signature; one original budget charge |
| Revocation, epoch change, reorg or deadline | New delivery stops without erasing old records/charges; historical signatures remain verifiable |
| Private candidate reads | Status/binding getter do not expose pending placeholder or response signature |
| Explicit relay limit | Copied signed request returns one unencrypted synthetic bundle without recipient private keys |

The existing authority-rollback and final-sample-to-arrival limitations remain.
This is not evidence of production isolation, global anti-rollback protection,
secure transport, human identity, real key release, factual truth, quantum
safety, customer integration or a completed independent audit. No private
custody session, funded transaction, mainnet action or live node was used.
