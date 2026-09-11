import json
from ersec_assurance_kernel import evaluate_report, verify_proof_artifact


def _reality():
    return {
        "schema": "ersec-reality/1",
        "version": "29.1.0",
        "target": "https://example.test",
        "reality_digest": "abc",
        "claims": [
            {"claim_id":"c1","dimension":"discovery","subject":"endpoint","statement":"surface observed","verdict":"observed","evidence_level":"medium","impact":0.3},
            {"claim_id":"c2","dimension":"authorization","subject":"auth","statement":"authorization verified","verdict":"verified","evidence_level":"high","impact":0.8},
            {"claim_id":"c3","dimension":"application-behavior","subject":"workflow","statement":"behavior observed","verdict":"observed","evidence_level":"medium","impact":0.5},
            {"claim_id":"c5","dimension":"input-safety","subject":"input","statement":"input observed","verdict":"observed","evidence_level":"medium","impact":0.4},
            {"claim_id":"c6","dimension":"transport-and-browser","subject":"transport","statement":"transport verified","verdict":"verified","evidence_level":"medium","impact":0.4},
            {"claim_id":"c7","dimension":"governance","subject":"scope","statement":"scope and safety governance observed","verdict":"verified","evidence_level":"medium","impact":0.3},
        ],
        "nodes": [],
        "assurance_frontier": [],
    }


def test_kernel_blocks_when_required_obligations_are_unproven():
    result = evaluate_report(_reality())
    assert result["version"] == "29.1.0"
    assert result["release_status"] == "BLOCKED"
    assert result["obligation_summary"]["blocked_or_unknown"] >= 1
    assert result["governance"]["absence_of_evidence_is_not_pass"] is True


def test_kernel_passes_when_all_required_dimensions_are_proven():
    report = _reality()
    report["claims"].extend([
        {"claim_id":"c4","dimension":"api-contract","subject":"api","statement":"contract verified","verdict":"verified","evidence_level":"medium","impact":0.4},
    ])
    result = evaluate_report(report)
    assert result["release_status"] == "PASS"


def test_proof_chain_is_self_verifying():
    result = evaluate_report(_reality())
    check = verify_proof_artifact(result)
    assert check["valid"] is True
    tampered = json.loads(json.dumps(result))
    if tampered["proof_chain"]:
        tampered["proof_chain"][0]["verdict"] = "violated"
    assert verify_proof_artifact(tampered)["valid"] is False
