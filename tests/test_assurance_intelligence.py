from ersec_assurance_intelligence import AssuranceIntelligence, analyze_report, diff_reports, VERSION, SCHEMA


def reality():
    return {
        "schema": "ersec-reality/1",
        "version": "29.1.0",
        "reality_digest": "r1",
        "claims": [
            {"claim_id":"auth-1","dimension":"authorization","subject":"order/1","verdict":"unknown","evidence_level":"none","impact":0.95},
            {"claim_id":"api-1","dimension":"api-contract","subject":"orders","verdict":"verified","evidence_level":"high","impact":0.6},
        ],
        "nodes": [{"label":"order/1"}],
        "edges": [{"source":"order/1","target":"orders"}],
    }


def test_intelligence_is_deterministic_except_timestamp():
    a = AssuranceIntelligence().analyze(reality(), budget=3)
    b = AssuranceIntelligence().analyze(reality(), budget=3)
    assert a["schema"] == SCHEMA
    assert a["version"] == VERSION == "29.1.0"
    assert a["assurance_intelligence_digest"] == b["assurance_intelligence_digest"]
    assert a["proof_debt_total"] > 0
    assert a["next_best_observations"]


def test_declared_but_unobserved_is_a_gap_not_a_failure_claim():
    result = analyze_report(reality(), declared={"endpoints":["/admin/export"]})
    assert any(g["kind"] == "declared-but-unobserved" for g in result["reality_gaps"])
    assert result["governance"]["absence_of_evidence_is_not_pass"] is True


def test_diff_detects_evidence_regression_and_not_disappearance_as_resolution():
    before = reality()
    after = reality()
    after["claims"] = [after["claims"][1]]
    result = diff_reports(before, after)
    assert result["status"] == "changed"
    removed = [x for x in result["claim_changes"] if x["claim_id"] == "auth-1"][0]
    assert removed["change"] == "removed"
    assert "not a remediation" in removed["interpretation"]


def test_budget_is_respected():
    result = analyze_report(reality(), budget=0.5)
    assert result["observation_budget"]["selected_cost"] <= 0.5
    assert result["observation_budget"]["remaining"] >= 0


def test_malformed_numbers_and_negative_budget_are_safe():
    bad = reality()
    bad["claims"][0]["impact"] = "not-a-number"
    result = analyze_report(bad, budget=-5)
    assert result["observation_budget"]["requested"] == 0.0
    assert result["observation_budget"]["selected_cost"] == 0.0
