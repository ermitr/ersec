import json

from ersec_assurance_lineage import build_oracle_lattice, build_research_artifact, compare_runs, oracle_trust, to_otel_events


def test_oracle_trust_lattice_orders_strength():
    assert oracle_trust("high")["score"] > oracle_trust("medium")["score"] > oracle_trust("low")["score"]


def test_counterfactual_delta_is_conservative():
    before = {"variants": [{"name": "fixed", "cases": [{"case_id": "C1", "verdict": "violation"}]}]}
    after = {"variants": [{"name": "fixed", "cases": [{"case_id": "C1", "verdict": "observation_unavailable"}]}]}
    result = compare_runs(before, after)
    assert result["status"] == "pass"
    assert result["deltas"][0]["transition"] == "remediation_unverified"


def test_lineage_never_contains_secret_values():
    benchmark = {
        "benchmark_id": "demo",
        "variants": [{"name": "fixed", "cases": [{"case_id": "C1", "verdict": "pass", "status": 200, "evidence": {"token": "SECRET-VALUE"}}]}],
        "methodology": {"corpus_manifest": {"corpus_digest": "abc"}},
    }
    artifact = build_research_artifact(benchmark)
    assert "SECRET-VALUE" not in json.dumps(artifact)


def test_frontier_is_explicit():
    artifact = build_research_artifact({"variants": []}, mutation={"survivors": [{"mutant_id": "m1", "targeted_dimension": "field", "description": "need observer", "priority": 5}]})
    assert artifact["assurance_frontier"]["count"] == 1
    assert artifact["assurance_frontier"]["items"][0]["id"] == "m1"


def test_lattice_marks_authoritative_separately():
    result = build_oracle_lattice([{"case_id": "C1", "oracle_strength": "high", "authoritative_observer": True}])
    assert result["counts"]["authoritative"] == 1


def test_otel_event_has_stable_name_and_dynamic_case_attribute():
    delta = compare_runs({"variants":[{"name":"x","cases":[{"case_id":"C1","verdict":"pass"}]}]}, {"variants":[{"name":"x","cases":[{"case_id":"C1","verdict":"violation"}]}]})
    events = to_otel_events(delta)
    assert events[0]["name"] == "ersec.security.assurance.delta"
    assert events[0]["attributes"]["ersec.case_id"] == "C1"
