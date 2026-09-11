import json
from pathlib import Path
from ersec_assurance_loop import IntegratedAssuranceLoop

def test_integrated_loop_offline(tmp_path):
    root=Path(__file__).resolve().parents[1]
    policy=root/'examples/security-behavior-policy-29.1.0.yaml'
    inventory=root/'examples/api-behavior-inventory-29.1.0.json'
    flow=root/'examples/stateful-business-flow-29.1.0.yaml'
    meta=root/'examples/metamorphic-security-29.1.0.json'
    base=root/'examples/counterfactual-baseline-29.1.0.json'
    mut=root/'examples/counterfactual-mutated-29.1.0.json'
    out=IntegratedAssuranceLoop.run(str(policy),str(inventory),str(flow),str(meta),str(base),str(mut),budget=5)
    assert out['version']=='29.1.0'
    assert out['governance']['network_contact'] is False
    assert out['artifacts']['kernel']['release_status'] in {'PASS','BLOCKED','FAIL'}
    assert len(out['integrated_digest'])==64

def test_integrated_loop_deterministic_except_intelligence_time(tmp_path):
    root=Path(__file__).resolve().parents[1]
    kwargs=dict(policy_path=str(root/'examples/security-behavior-policy-29.1.0.yaml'),inventory_path=str(root/'examples/api-behavior-inventory-29.1.0.json'))
    a=IntegratedAssuranceLoop.run(**kwargs); b=IntegratedAssuranceLoop.run(**kwargs)
    assert a['artifacts']['reality']['reality_digest']==b['artifacts']['reality']['reality_digest']
    assert a['artifacts']['kernel']['release_certificate_digest']==b['artifacts']['kernel']['release_certificate_digest']
