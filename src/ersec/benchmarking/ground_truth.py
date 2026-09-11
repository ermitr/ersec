"""
ERSEC Authorization Ground Truth Manifest.
Stores the authoritative expected results for authorization test cases
independently of the detection logic to prevent circular validation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

@dataclass(frozen=True)
class AuthTestCase:
    case_id: str
    family: str
    description: str
    path: str
    method: str = "GET"
    # Expected results for different identity roles
    # Role -> Expected Result ("pass" | "violation" | "blocked")
    expectations: Dict[str, str] = field(default_factory=dict)
    # Specific fields that MUST be absent or present in a violation
    sensitive_fields: Set[str] = field(default_factory=set)
    # Baseline if the case is a "fixed" variant
    fixed_variant_id: Optional[str] = None

# THE GOLDEN CORPUS
# These cases are designed to test the specific a-priori categories
# mentioned in the Implementation Brief.
GROUND_TRUTH = {
    # 1. Vertical Privilege Escalation (Admin exposure)
    "VPE-01": AuthTestCase(
        case_id="VPE-01",
        family="vertical_pe",
        description="Access to administrative user list from user role",
        path="/rest/admin/users",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
        sensitive_fields={"emails", "hashed_passwords", "roles"}
    ),

    # 2. Horizontal Privilege Escalation (BOLA / IDOR)
    "BOLA-01": AuthTestCase(
        case_id="BOLA-01",
        family="horizontal_pe",
        description="Access to another user's profile",
        path="/rest/user/1", # Case where current user is NOT 1
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
        sensitive_fields={"address", "phone_number"}
    ),

    # 3. Cross-Tenant Object Access
    "CTOA-01": AuthTestCase(
        case_id="CTOA-01",
        family="cross_tenant",
        description="Access to resource belonging to a different tenant",
        path="/api/tenantB/orders/123", # Current user is in tenantA
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
        sensitive_fields={"order_total", "customer_name"}
    ),

    # 4. Function-Level Authorization Failure
    "FLAF-01": AuthTestCase(
        case_id="FLAF-01",
        family="function_level",
        description="Execution of administrative function via method confusion (e.g. POST instead of GET)",
        path="/api/admin/reset-password",
        method="POST",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
    ),

    # 5. Hidden Sensitive-Field Exposure
    "HSFE-01": AuthTestCase(
        case_id="HSFE-01",
        family="field_exposure",
        description="Response contains internal sensitive fields not intended for users",
        path="/api/user/me",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
        sensitive_fields={"internal_debug_id", "db_primary_key"}
    ),

    # 6. Mass Assignment
    "MA-01": AuthTestCase(
        case_id="MA-01",
        family="mass_assignment",
        description="Updating privileged fields (e.g. is_admin) via profile update",
        path="/api/user/update",
        method="PUT",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
    ),

    # 7. Method Confusion
    "MC-01": AuthTestCase(
        case_id="MC-01",
        family="method_confusion",
        description="Accessing resource via unexpected HTTP method (e.g. PUT on read-only resource)",
        path="/api/public/info",
        method="PUT",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
    ),

    # 8. Multi-step Workflow Bypass
    "MWB-01": AuthTestCase(
        case_id="MWB-01",
        family="workflow_bypass",
        description="Skipping payment step to reach order-confirmation",
        path="/api/checkout/confirm",
        method="POST",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
    ),

    # 9. Ownership Transfer Error
    "OTE-01": AuthTestCase(
        case_id="OTE-01",
        family="ownership_transfer",
        description="Changing ownership of a resource to oneself without authorization",
        path="/api/resource/transfer",
        method="POST",
        expectations={"admin": "pass", "user": "violation", "anonymous": "blocked"},
    ),

    # 10. Correctly Secured Negative Control
    "NEG-01": AuthTestCase(
        case_id="NEG-01",
        family="baseline",
        description="Attempt to access clearly restricted resource (should be correctly blocked)",
        path="/etc/passwd",
        expectations={"admin": "blocked", "user": "blocked", "anonymous": "blocked"},
    ),

    # 11. Nondeterministic Response Fixture
    "NDRF-01": AuthTestCase(
        case_id="NDRF-01",
        family="nondeterministic",
        description="Resource with volatile fields (timestamps, IDs) that should not affect verdict",
        path="/api/status",
        expectations={"admin": "pass", "user": "pass", "anonymous": "pass"},
        sensitive_fields=set(), # Nothing sensitive, just volatile
    ),
}

def get_ground_truth() -> Dict[str, AuthTestCase]:
    return GROUND_TRUTH
