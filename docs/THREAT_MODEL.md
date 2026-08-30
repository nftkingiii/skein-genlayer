# Threat model

## Assets

- The off-chain context protected by a policy.
- Policy ownership and version integrity.
- The binding between requester, atomic scope, decision, and expiry.
- The auditability of denial and review outcomes.

## Trust boundaries

1. A policy owner submits public natural-language policy text.
2. A requester submits public purpose and metadata labels.
3. Validators produce untrusted model output.
4. An off-chain retrieval service consumes a receipt and releases context.

## Principal abuse cases and controls

| Abuse case | Control |
| --- | --- |
| Requester impersonates another agent | Requester is bound to `gl.message.sender_address`; it is not a user parameter. |
| Request widens an approved scope | One atomic scope per request; deterministic exact-scope equality. |
| Model invents a permissive clause | Clause must exist in the owner-declared clause ID set. |
| Model smuggles authority into a denial | `DENY` and `REVIEW` require empty scope and zero TTL. |
| Prompt injection in policy/request fields | Values are delimited and marked as untrusted; validators independently compare decisions; output is schema-checked. This mitigates but cannot eliminate model-level injection. |
| Old approval survives a policy change | Receipt validity requires the current active policy version to match. |
| Approval is replayed by another agent | Receipt validity binds the caller-supplied requester address to the original transaction sender. |
| Approval is replayed for another resource | Receipt validity requires exact scope equality. |
| Oversized input causes excessive model work | Contract caps policy, purpose, metadata, scope, identifiers, and TTL. |
| Sensitive data leaks through the contract | Architecture forbids sensitive context in calldata; contract stores only request hashes and public authorization metadata. |
| Retrieval service ignores the receipt | Out of scope for an on-chain primitive. Integrators must fail closed and check immediately before retrieval. |

## Residual risks

- All contract inputs are public, including values later represented by hashes.
- Policy ambiguity can produce inconsistent validator decisions or `REVIEW`.
- A malicious policy owner can write a permissive policy; Skein enforces policy
  provenance and interpretation, not the owner's intent or legal compliance.
- A compromised retrieval service can bypass Skein unless enforcement is made
  mandatory at that service boundary.

