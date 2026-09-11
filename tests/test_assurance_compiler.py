import json
from pathlib import Path

from ersec.ersec_assurance_compiler import (
    VERSION, build_inventory, compile_policy, evaluate_runtime_controls,
    merge_observations, parse_policy, validate_plan, load_document,
)

ROOT = Path(__file__).resolve().parents[1]


def test_policy_compile_is_deterministic_and_versioned():
    doc = load_document(str(ROOT / "examples" / "security-behavior-policy-29.1.1.yaml"))
    result = compile_policy(doc)
    assert VERSION == "29.1.1"
    assert result["version"] == "29.1.1"
    assert result["validation"]["valid"] is True
    assert len(result["assurance_cells"]) >= 3
    assert result["compile_digest"]
    assert validate_plan(result)["valid"] is True


def test_inventory_normalizes_and_deduplicates():
    result = build_inventory(load_document(str(ROOT / "examples" / "api-behavior-inventory-29.1.1.json")))
    assert result["operation_count"] == 3
    assert result["observed_count"] == 2
    assert result["declared_only_count"] == 1
    assert result["digest"]


def test_runtime_controls_never_promote_configured_to_enforced():
    doc = load_document(str(ROOT / "examples" / "runtime-control-evidence-29.1.1.json"))
    result = evaluate_runtime_controls(doc)
    assert result["counts"]["observed_enforced"] == 1
    assert result["counts"]["configured_only"] == 1
    assert result["controls"][1]["state"] == "configured_only"


def test_evidence_merge_preserves_not_tested():
    policy = load_document(str(ROOT / "examples" / "security-behavior-policy-29.1.1.yaml"))
    plan = compile_policy(policy)
    evidence = [{"cell_id": plan["assurance_cells"][0]["id"], "verdict": "pass", "evidence_refs": ["e1"]}]
    merged = merge_observations(plan, evidence)
    assert merged["coverage"]["tested"] == 1
    assert merged["coverage"]["not_tested"] == len(plan["assurance_cells"]) - 1
    assert any(c["status"] == "not_tested" for c in merged["assurance_cells"])
