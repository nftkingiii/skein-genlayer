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
- `DENY` and `REVIEW` cannot carry scope or TTL;
- updating or revoking a policy invalidates old receipts.

## Public-data boundary

GenLayer contract source, calldata, prompts, outputs, and storage must be treated
as public. Never submit private memory, document contents, secrets, personal
data, credentials, or raw retrieval results to Skein.

`purpose` and `context_metadata` must contain non-sensitive labels or booleans,
for example:

```text
purpose: Resolve the authenticated customer's open support request
context_metadata: tenant_match=true;authenticated_customer=true
```

Only SHA-256 hashes of those two fields are retained in receipts. Hashing does
not make low-entropy or sensitive calldata private; the original transaction
input remains public.

## Contract lifecycle

1. A policy owner calls `create_policy` with stable clause identifiers.
2. An agent calls `request_access` for one atomic resource scope.
3. Validators reason over the policy and public request metadata.
4. Skein validates and stores the consensus result.
5. The off-chain retrieval boundary calls `is_receipt_valid` immediately before
   releasing context.
6. Policy updates, revocation, expiry, requester mismatch, or scope mismatch
   fail closed.

## Example policy

```text
P1: Support agents may read account.profile for the purpose of resolving an
authenticated customer's open support request when tenant_match=true.
P2: Marketing, model training, prospecting, and cross-tenant access are denied.
P3: If tenant_match or authenticated_customer is missing, require human review.
```

Use `P1,P2,P3` as `clause_ids_csv`. Clause IDs are validated and the LLM may not
invent a new one.

## Methods

### Writes

- `create_policy(policy_id, name, policy_text, clause_ids_csv, max_ttl_seconds)`
- `update_policy(policy_id, name, policy_text, clause_ids_csv, max_ttl_seconds)`
- `revoke_policy(policy_id)`
- `request_access(policy_id, resource_scope, purpose, context_metadata)`

### Views

- `get_policy(policy_id)`
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
output, scope broadening, unknown clauses, input bounds, and validator dissent.

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

## License

MIT
