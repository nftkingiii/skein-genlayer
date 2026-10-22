# SkeinPolicyGate

SkeinPolicyGate is a reusable GenLayer Intelligent Contract for **permission
before inference**. It evaluates whether an agent may access one atomic resource
scope under a versioned natural-language policy, then stores an expiry-bound
`ALLOW`, `DENY`, or `REVIEW` receipt.

It is a contract primitive, not a frontend or data vault. Sensitive context
stays off-chain. A retrieval service can release context only after it calls
`is_receipt_valid` and confirms that the receipt still matches the requester,
scope, active policy version, and transaction-time expiry.

## Why this needs GenLayer

Traditional access control handles deterministic checks such as roles and
allowlists well. It struggles with contextual rules such as:

> A support agent may read an authenticated customer's profile only to resolve
> that customer's open ticket, but never for model training or cross-tenant use.

Skein uses GenLayer's leader-validator consensus so each validator independently
assesses the same public request metadata against the same policy. A custom
equivalence check accepts the leader's decision only when all security-relevant
fields match: verdict, clause, reason code, exact scope, TTL, and policy version.

The contract then applies deterministic checks to the consensus result:

- only `ALLOW`, `DENY`, and `REVIEW` are accepted;
- `ALLOW` must cite a declared clause;
- the authorized scope must exactly equal the requested atomic scope;
- TTL must be inside the policy owner's bound;
- `DENY` and `REVIEW` cannot carry scope, TTL, or facts;
- every fact an `ALLOW` depends on must be attested on chain (see below);
- updating or revoking a policy invalidates old receipts.

## Verified facts: who says a fact is true

Validators can agree on how to *read* a request, but agreement is not evidence
that a fact is true. So Skein never lets the requester establish a fact.

- The policy owner declares `fact_keys_csv` (every fact a clause may depend on),
  `required_facts_csv` (facts every `ALLOW` needs), and `attesters_csv` (the
  wallets allowed to vouch for those facts, such as the tenant's identity or
  support backend).
- An authorized attester calls `attest(policy_id, subject_address,
  resource_scope, facts_csv, ttl_seconds)`. The attester is the transaction
  sender, so the source of each fact is verified by the chain itself. An
  attestation names one subject and one exact scope, and expires.
- `request_access` reads the requester's live attestation from storage and gives
  validators two separate inputs: `VERIFIED_FACTS` (from the attestation) and
  `UNVERIFIED_REQUESTER_NOTE` (the requester's own text).
- The model must return `facts_relied_on`. After consensus, a deterministic gate
  turns any `ALLOW` into `REVIEW / UNVERIFIED_FACTS` unless every required fact
  and every fact relied on is in the attestation. No wording in the request can
  satisfy it.
- A receipt records its attestation and cannot outlive it. Revoking the
  attestation, letting it expire, or removing the attester from the policy makes
  `is_receipt_valid` return false.

## Public-data boundary

GenLayer contract source, calldata, prompts, outputs, and storage must be treated
as public. Never submit private memory, document contents, secrets, personal
data, credentials, or raw retrieval results to Skein.

`purpose` and `requester_note` are public and unverified. Attested facts are
bare, non-sensitive keys such as `tenant_match` or `authenticated_customer`,
bound to a wallet address and a scope, never to a person's identity:

```text
attest: facts_csv = authenticated_customer,tenant_match
purpose: Resolve the authenticated customer's open support request
requester_note: Ticket is open in the support queue
```

Only SHA-256 hashes of `purpose` and `requester_note` are retained in receipts.
Hashing does not make low-entropy or sensitive calldata private; the original
transaction input remains public.

## Contract lifecycle

1. A policy owner calls `create_policy` with clause ids, fact keys, required
   facts, and authorized attesters.
2. An authorized attester calls `attest` for the agent's address and one scope.
3. The agent calls `request_access` for that atomic resource scope.
4. Validators reason over the policy, the verified facts, and the unverified note.
5. Skein validates the consensus result and enforces the verified-fact gate.
6. The off-chain retrieval boundary calls `is_receipt_valid` immediately before
   releasing context.
7. Policy updates, policy or attestation revocation, expiry, requester mismatch,
   or scope mismatch fail closed.

## Example policy

```text
P1: Support agents may read account.profile for the purpose of resolving an
authenticated customer's open support request when tenant_match and
authenticated_customer are verified.
P2: Marketing, model training, prospecting, and cross-tenant access are denied.
P3: If tenant_match or authenticated_customer is not verified, require human review.
```

Use `P1,P2,P3` as `clause_ids_csv` and `authenticated_customer,tenant_match` as
both `fact_keys_csv` and `required_facts_csv`. Clause IDs and fact keys are
validated; the LLM may not invent either.

## Methods

### Writes

- `create_policy(policy_id, name, policy_text, clause_ids_csv, fact_keys_csv, required_facts_csv, attesters_csv, max_ttl_seconds)`
- `update_policy(...)` with the same arguments; bumps the policy version
- `revoke_policy(policy_id)`
- `attest(policy_id, subject_address, resource_scope, facts_csv, ttl_seconds)`
- `revoke_attestation(attestation_id)` (attester or policy owner)
- `request_access(policy_id, resource_scope, purpose, requester_note)`

### Views

- `get_policy(policy_id)`
- `get_attestation(attestation_id)`
- `get_receipt(receipt_id)`
- `is_receipt_valid(receipt_id, requester_address, resource_scope)`

## Local verification

Requirements: Python 3.12+.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest tests\direct -v
.\.venv\Scripts\genvm-lint.exe check contracts\SkeinPolicyGate.py
```

Direct tests cover authorization receipts, denial/review behavior, owner-only
policy changes, policy-version invalidation, revocation, expiry, malformed model
output, scope broadening, unknown clauses, input bounds, and validator dissent,
plus the verified-fact boundary: requester-claimed facts, partial attestations,
unauthorized attesters, undeclared facts, attestations reused by another
requester or scope, attestation revocation, and receipts capped at attestation
expiry.

## Deploy

After selecting a GenLayer network with the CLI:

```powershell
genlayer deploy --contract contracts\SkeinPolicyGate.py
```

Deployment and live multi-validator behavior are intentionally separate from
the source contribution. Record the deployed address and transaction only after
the intended network and contract revision have been verified.

## Limitations

- Skein proves a consensus-backed authorization decision, not confidentiality.
- The caller enforcing the receipt must be trustworthy and must check it just
  before retrieval.
- Natural-language policies can be ambiguous; `REVIEW` is a required fail-closed
  state, not an error to bypass.
- Leader-validator LLM consensus reduces single-model dependence but does not make a
  poorly written policy safe.
- Hashes attest to exact public inputs; they do not prove off-chain data quality.
- Skein verifies who attested a fact, not that the attester is honest. Choose
  attesters that already own the fact (the tenant's identity or support system)
  and keep attestation lifetimes short.

## License

MIT
