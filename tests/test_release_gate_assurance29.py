from ersec import ReleaseAssuranceGate

def base(): return {"findings":[],"coverage_matrix":{"coverage_ratio":1.0}}

def test_assurance_layers_gate():
    r=ReleaseAssuranceGate.evaluate(base(), contracts={"contracts":[]}, sbom={"bomFormat":"CycloneDX","specVersion":"1.7"}, mutation={"summary":{"mutation_adequacy":1.0}}, counterfactual={"status":"pass"}, runtime_controls={"counts":{"observed_gap":0,"insufficient_telemetry":0}})
    assert r["status"]=="pass"

def test_mutation_gate_blocks_weak_adequacy():
    r=ReleaseAssuranceGate.evaluate(base(), contracts={"contracts":[]}, sbom={"bomFormat":"CycloneDX","specVersion":"1.7"}, mutation={"summary":{"mutation_adequacy":0.5}})
    assert r["status"]=="fail"
