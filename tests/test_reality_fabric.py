import json
from ersec.ersec_reality import SecurityRealityFabric, SCHEMA


def report():
    return {
        "target": "https://example.test",
        "endpoints": ["https://example.test/", "https://example.test/api/orders/1"],
        "findings": [
            {"finding_id": "F-AUTH", "category": "idor", "title": "Cross-tenant object access", "severity": "high", "confidence": "Confirmed", "url": "https://example.test/api/orders/1"},
            {"finding_id": "F-LOW", "category": "header", "title": "Missing header", "severity": "low", "confidence": "Likely", "url": "https://example.test/"},
        ],
        "security_behavior_graph": {
            "invariants": [
                {"name": "tenant-isolation", "statement": "Tenant A must not read Tenant B objects", "verdict": "not_tested", "evidence": "none", "impact": 1.0}
            ]
        }
    }


def test_compile_is_deterministic_and_has_frontier():
    fabric = SecurityRealityFabric()
    a = fabric.compile(report())
    b = fabric.compile(report())
    assert a["schema"] == SCHEMA
    assert a["reality_digest"] == b["reality_digest"]
    assert a["assurance_frontier"]
    assert any(x["dimension"] == "authorization" for x in a["assurance_frontier"])
    assert a["posture"]["authorization"]["state"] == "risk"


def test_diff_detects_regression_and_resolution():
    fabric = SecurityRealityFabric()
    before = fabric.compile(report())
    after_source = report()
    after_source["findings"][0]["confidence"] = "Confirmed"
    # Turn the invariant into an explicit pass while keeping the same claim id.
    after_source["security_behavior_graph"]["invariants"][0]["verdict"] = "pass"
    after = fabric.compile(after_source)
    diff = fabric.diff(before, after)
    assert diff["changed_claims"]
    assert any(x.get("change") == "changed" for x in diff["changed_claims"])


def test_unknown_never_becomes_pass_by_disappearance():
    fabric = SecurityRealityFabric()
    before = fabric.compile(report())
    after_source = report()
    after_source["security_behavior_graph"]["invariants"] = []
    after = fabric.compile(after_source)
    diff = fabric.diff(before, after)
    assert all(x.get("change") != "changed" or x.get("after", {}).get("verdict") != "pass" for x in diff["changed_claims"])


def test_identical_reality_reports_are_unchanged():
    fabric = SecurityRealityFabric()
    artifact = fabric.compile(report())
    diff = fabric.diff(artifact, artifact)
    assert diff["status"] == "unchanged"
