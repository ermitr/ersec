from ersec_continuous_assurance import build_contract, evaluate_history, snapshot

def bundle(status='PASS', claims=None):
    return {'version':'29.1.0','integrated_digest':'a'*64,'artifacts':{
        'reality':{'reality_digest':'b'*64,'claims': claims or []},
        'kernel':{'release_status':status,'release_certificate_digest':'c'*64,'obligations':[]}}}

def test_pass_to_unknown_is_regression():
    b=bundle(claims=[{'claim_id':'x','status':'PASS'}]); a=bundle(claims=[{'claim_id':'x','status':'INCONCLUSIVE'}])
    r=build_contract(b,a); assert r['decision']=='FAIL'; assert r['regressions'][0]['transition']=='assurance_regression'

def test_explicit_improvement_passes():
    b=bundle(claims=[{'claim_id':'x','status':'INCONCLUSIVE'}]); a=bundle(claims=[{'claim_id':'x','status':'PASS'}])
    r=build_contract(b,a); assert r['decision']=='PASS'; assert r['transitions'][0]['transition']=='verified_improvement'

def test_history_chain_deterministic():
    b=bundle(); r1=evaluate_history(b,[b]); r2=evaluate_history(b,[b]); assert r1['history_digest']==r2['history_digest']

def test_snapshot_has_29():
    assert snapshot(bundle())['version']=='29.1.0'
