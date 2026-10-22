# Threat model

## Assets

- The off-chain context protected by a policy.
- Policy ownership and version integrity.
- The binding between requester, atomic scope, decision, and expiry.
- The auditability of denial and review outcomes.

## Trust boundaries

1. A policy owner submits public natural-language policy text.
2. An authorized attester (named by the policy owner) records facts on chain.
3. A requester submits a public purpose and an unverified note.
4. Validators produce untrusted model output.
5. An off-chain retrieval service consumes a receipt and releases context.

## Principal abuse cases and controls

| Abuse case | Control |
| --- | --- |
| Requester asserts facts it cannot prove (for example `tenant_match=true`) | Requester text is labelled unverified in the prompt, and a deterministic post-consensus gate downgrades any `ALLOW` to `REVIEW / UNVERIFIED_FACTS` unless every required fact and every fact relied on is in a live on-chain attestation. |
| Unauthorized party vouches for a fact | `attest` requires the transaction sender to be in the policy's `attesters_csv`; facts must be declared by the policy. |
| Attestation reused by another agent or for another resource | Attestations are keyed by policy, subject address, and exact scope. |
| Approval outlives the facts behind it | Receipts store their attestation id; expiry is capped at the attestation's; revocation, expiry, or attester removal invalidates the receipt. |
| Model relies on a fact the policy never declared | `facts_relied_on` must be a subset of declared fact keys, and it is one of the seven fields validators must agree on. |
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
- A compromised or careless attester can vouch for false facts. Skein proves who
  attested and when, and lets the attester or owner revoke, but cannot prove the
  attester is honest.
- A malicious policy owner can write a permissive policy; Skein enforces policy
  provenance and interpretation, not the owner's intent or legal compliance.
- A compromised retrieval service can bypass Skein unless enforcement is made
  mandatory at that service boundary.

