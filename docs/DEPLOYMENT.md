# Deployment

## GenLayer Studio (studionet)

| | |
|---|---|
| Network | GenLayer Studio, `https://studio.genlayer.com/api`, chain ID 61999 |
| Contract | `0x4EfeF2F6a805ADA20f97EF5d648175F0572ef86a` |
| Deploy transaction | `0xaff1a6d69de8c148a644e02a2dd94b3c64df673026727068951ac46d7d34422a` |
| Source | `contracts/SkeinPolicyGate.py` at commit `3caf11ec18a4534390b3a4eb5e9dbd3d68aa4cfc` |
| Source SHA-256 | `1c1981be4219055953c576c93c2b7861329cfbaeea2e40fe3b3d9845d906d6a9` |
| Deployed | 2026-10-22 |

The code returned by `gen_getContractCode` for the contract address has the same
SHA-256 as the source file at that commit.

Check it yourself (PowerShell):

```powershell
$body = '{"jsonrpc":"2.0","id":1,"method":"gen_getContractCode","params":["0x4EfeF2F6a805ADA20f97EF5d648175F0572ef86a"]}'
$code = (Invoke-RestMethod -Uri https://studio.genlayer.com/api -Method Post -ContentType 'application/json' -Body $body).result
$bytes = [Convert]::FromBase64String($code)
[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLower()
```

## Live run (2026-10-22)

Three separate wallets: policy owner `0x334aED7CE8f5D65404bB92280232053f2121A4F4`,
attester `0x8228d5cCa295C270389fB3a72F5347Fdb3eFec57`, agent
`0x3Dc59160C8056Eb75DBC5F1a3fcb65E143c21e4c`. Policy `support-memory-v1` uses the
example policy from the README, with `authenticated_customer,tenant_match` as fact
keys and required facts, and the attester as the only authorized attester. Every
transaction below reached `MAJORITY_AGREE` among Studio's validators, which run
different models.

| Step | Transaction | Outcome |
|---|---|---|
| `create_policy` (owner) | `0xf4f828578fa2d8064ace9229237fa290fd71fda49296431aaf3ae4cb80c5d546` | Policy v1 |
| `request_access` (agent) with note `tenant_match=true;authenticated_customer=true`, no attestation | `0x10ed54af40297e3fa1bc1f83609fbd068cd6e50b1fb341e9277ba38b30073e5c` | `REVIEW`, `is_receipt_valid` false |
| `attest` (attester) for the agent and `account.profile` | `0x24351a9952d911ec987f62a62caf5857737809d88d0e67e346a3518ea3282c7d` | Attestation `e79fc951…bc38` |
| `request_access` (agent) to resolve a support request | `0x4b154fa6bb7dbe6f499a861fc7158cdd3b7f7a33bc5af5410d9558d86f04d7a1` | `ALLOW`, clause `P1`, `POLICY_PERMITS`, valid |
| `request_access` (agent) to train a marketing model | `0x42729572ddf261d2f755d3daee501f038b9554a8eb4660b196f5261287780f9e` | `DENY`, clause `P2`, `POLICY_FORBIDS` |
| `revoke_attestation` (attester) | `0x46602ed750376a4dd2fa7ac39eb86cfebb1148aa9ed2d35eb755f968d567016e` | Earlier `ALLOW` receipt now invalid |

The first request is the case from the review: the requester asserts the facts,
and the contract does not authorize access without an attestation from an
authorized attester.
