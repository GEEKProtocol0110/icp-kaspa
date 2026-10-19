# Native ticket design checkpoint

Date: October 19, 2026. Attribution: ICP contributors.

Scope: offline engineering review of the proposed
[N0 native ticket design](../docs/NATIVE-TICKET-DESIGN.md). This is a design
record, not a transaction transcript or independent security assessment.

## Decisions recorded

| Question | Proposed N0 decision |
| --- | --- |
| Native layout | One P2PK funding input creates ticket at index 0 and funding change at index 1; terminal spend returns to a distinct pinned native key |
| Authority | Funding, ticket and return roles are distinct; ordinary P2PK does not enforce service permission/expiry/quota |
| Economics | Ticket 12,000,000 sompi; fee 2,000,000 per action; terminal return 10,000,000; issue source 24,000,000–100,000,000 |
| Commitment order | Intent and issue precede known issuance ID; recipient admission precedes consume ID; response binds known consume ID |
| Refund eligibility | Expired/revoked, permanently closed, never-reserved ticket only; new purpose-bound cleanup approval; no restored permission or quota |
| Terminal conflict | Permanent consume/refund choice before signing; no automatic switch, replacement, fee bump or rebroadcast |
| Recovery | Independent continuity/fencing requirements; unknown effects read-only; preserve outboxes, claims, charges, closures and disclosure history |

The source review used the repository-pinned rusty-kaspa revision
`a41a333b08848f41bf737b72592e463a6011b8ac`, specifically native signature hashing,
V1 transaction hashing and standard P2PK script construction. Exact links and
the existing anchor-preparer reference are in the design. No upstream source
or dependency was changed.

Two important distinctions are explicit: V1 IDs/signatures do not commit every
saved transaction field, and service expiry/fencing cannot retract copied
native signed bytes. Their proposed acceptance tests are future work, not
newly demonstrated properties in this checkpoint.

## Validation and limits

- Pinned Python dependencies were installed/confirmed. Existing full Python
  suite passed: **379 tests**, with no test or application source changes.
- Existing complete implementation count remains **447: 68 Rust + 379 Python**.
  Rust is unavailable on the refreshed local host; required format, native
  tests, template compilation, build and full-suite checks run in GitHub CI.
  Final check results belong to the associated PR and its exact tested head.
- Documentation links, candidate amount arithmetic, tracked-source checksums
  and whitespace are checked before publication.
- No new tests were added solely for documentation. No native builder or
  journal/controller/observer implementation, actual ticket, RPC, broadcast,
  funded session change, real content key or remote release was introduced.
- Fixed fees, compute budget and output amounts are candidate parameters.
  They have no new native mass/relay/fee or public TN10 acceptance measurement.
- Complete closed schemas/signature domains/vectors, native mutation tests,
  independently enforced signer continuity, dedicated observer and protected
  real-key/transport boundaries remain separate gates.

Next: implement only the offline native preparer and adversarial mutation suite
with fabricated UTXOs and public fixture keys. It must not gain RPC, broadcast
or release-model integration in that milestone.
