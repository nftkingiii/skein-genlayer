import json

import pytest


POLICY_TEXT = """
P1: Support agents may read account.profile for the purpose of resolving an
authenticated customer's open support request when tenant_match=true.
P2: Marketing, model training, prospecting, and cross-tenant access are denied.
P3: If tenant_match or authenticated_customer is missing, require human review.
""".strip()


def deploy_with_policy(direct_vm, direct_deploy):
    direct_vm.check_pickling = True
    contract = direct_deploy("contracts/SkeinPolicyGate.py")
    contract.create_policy(
        "support-memory-v1",
        "Support memory access",
        POLICY_TEXT,
        "P1,P2,P3",
        3600,
    )
    return contract


def mock_decision(direct_vm, **overrides):
    decision = {
        "verdict": "ALLOW",
        "clause_id": "P1",
        "reason_code": "EXPLICIT_POLICY_MATCH",
        "authorized_scope": "account.profile",
        "ttl_seconds": 300,
        "policy_version": 1,
    }
    decision.update(overrides)
    direct_vm.mock_llm(r".*pre-inference authorization request.*", json.dumps(decision))


def test_allow_receipt_is_scoped_and_valid(
    direct_vm,
    direct_deploy,
    direct_owner,
):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    direct_vm.warp("2026-08-30T12:00:00Z")
    mock_decision(direct_vm)

    receipt_id = contract.request_access(
        "support-memory-v1",
        "account.profile",
        "Resolve the authenticated customer's open support request",
        "tenant_match=true;authenticated_customer=true",
    )

    receipt = contract.get_receipt(receipt_id)
    assert receipt["verdict"] == "ALLOW"
    assert receipt["clause_id"] == "P1"
    assert receipt["resource_scope"] == "account.profile"
    assert receipt["purpose_hash"]
    assert receipt["metadata_hash"]
    assert contract.is_receipt_valid(receipt_id, receipt["requester"], "account.profile")
    assert not contract.is_receipt_valid(receipt_id, receipt["requester"], "account.billing")


@pytest.mark.parametrize("verdict,clause,reason", [
    ("DENY", "P2", "PROHIBITED_PURPOSE"),
    ("REVIEW", "P3", "MISSING_REQUIRED_FACTS"),
])
def test_non_allow_receipts_never_authorize(
    direct_vm,
    direct_deploy,
    direct_owner,
    verdict,
    clause,
    reason,
):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    mock_decision(
        direct_vm,
        verdict=verdict,
        clause_id=clause,
        reason_code=reason,
        authorized_scope="",
        ttl_seconds=0,
    )

    receipt_id = contract.request_access(
        "support-memory-v1",
        "account.profile",
        "Train a marketing model",
        "tenant_match=true",
    )

    assert contract.get_receipt(receipt_id)["verdict"] == verdict
    requester = contract.get_receipt(receipt_id)["requester"]
    assert not contract.is_receipt_valid(receipt_id, requester, "account.profile")


def test_only_policy_owner_can_update(
    direct_vm,
    direct_deploy,
    direct_bob,
):
    contract = deploy_with_policy(direct_vm, direct_deploy)

    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("Only the policy owner"):
            contract.update_policy(
                "support-memory-v1",
                "Hijacked",
                "P1: Allow everything.",
                "P1",
                3600,
            )


def test_policy_update_invalidates_existing_allow_receipt(
    direct_vm,
    direct_deploy,
    direct_owner,
):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    mock_decision(direct_vm)
    receipt_id = contract.request_access(
        "support-memory-v1",
        "account.profile",
        "Resolve the authenticated customer's open support request",
        "tenant_match=true;authenticated_customer=true",
    )
    requester = contract.get_receipt(receipt_id)["requester"]
    assert contract.is_receipt_valid(receipt_id, requester, "account.profile")

    contract.update_policy(
        "support-memory-v1",
        "Support memory access v2",
        POLICY_TEXT + "\nP4: Approval expires when the policy is updated.",
        "P1,P2,P3,P4",
        1800,
    )

    assert not contract.is_receipt_valid(receipt_id, requester, "account.profile")


def test_revocation_invalidates_existing_allow_receipt(
    direct_vm,
    direct_deploy,
    direct_owner,
):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    mock_decision(direct_vm)
    receipt_id = contract.request_access(
        "support-memory-v1",
        "account.profile",
        "Resolve the authenticated customer's open support request",
        "tenant_match=true;authenticated_customer=true",
    )

    contract.revoke_policy("support-memory-v1")

    requester = contract.get_receipt(receipt_id)["requester"]
    assert not contract.is_receipt_valid(receipt_id, requester, "account.profile")


def test_expiry_invalidates_allow_receipt(
    direct_vm,
    direct_deploy,
    direct_owner,
):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    direct_vm.warp("2026-08-30T12:00:00Z")
    mock_decision(direct_vm, ttl_seconds=60)
    receipt_id = contract.request_access(
        "support-memory-v1",
        "account.profile",
        "Resolve the authenticated customer's open support request",
        "tenant_match=true;authenticated_customer=true",
    )

    direct_vm.warp("2026-08-30T12:01:01Z")

    requester = contract.get_receipt(receipt_id)["requester"]
    assert not contract.is_receipt_valid(receipt_id, requester, "account.profile")


def test_malformed_or_scope_broadening_output_reverts(direct_vm, direct_deploy):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    mock_decision(direct_vm, authorized_scope="account.*")

    with direct_vm.expect_revert("broadened or changed scope"):
        contract.request_access(
            "support-memory-v1",
            "account.profile",
            "Resolve a support request",
            "tenant_match=true;authenticated_customer=true",
        )


def test_unknown_clause_output_reverts(direct_vm, direct_deploy):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    mock_decision(direct_vm, clause_id="P999")

    with direct_vm.expect_revert("unknown policy clause"):
        contract.request_access(
            "support-memory-v1",
            "account.profile",
            "Resolve a support request",
            "tenant_match=true;authenticated_customer=true",
        )


def test_consensus_disagrees_when_validator_changes_decision(direct_vm, direct_deploy):
    contract = deploy_with_policy(direct_vm, direct_deploy)
    mock_decision(direct_vm)
    contract.request_access(
        "support-memory-v1",
        "account.profile",
        "Resolve a support request",
        "tenant_match=true;authenticated_customer=true",
    )

    direct_vm.clear_mocks()
    mock_decision(
        direct_vm,
        verdict="DENY",
        clause_id="P2",
        reason_code="PROHIBITED_PURPOSE",
        authorized_scope="",
        ttl_seconds=0,
    )
    assert direct_vm.run_validator() is False


def test_rejects_private_or_oversized_payload_shapes(direct_vm, direct_deploy):
    contract = deploy_with_policy(direct_vm, direct_deploy)

    with direct_vm.expect_revert("purpose is too long"):
        contract.request_access(
            "support-memory-v1",
            "account.profile",
            "x" * 1001,
            "tenant_match=true",
        )

    with direct_vm.expect_revert("context_metadata is too long"):
        contract.request_access(
            "support-memory-v1",
            "account.profile",
            "Resolve a support request",
            "x" * 2001,
        )
