from ersec.ersec_release_evidence import build_release_evidence, verify_release_evidence, property_id, build_remediation_contract

def bundle():
    return {'version':'29.1.1','integrated_digest':'a'*64,'artifacts':{'reality':{'reality_digest':'b'*64},'kernel':{'release_status':'PASS','release_certificate_digest':'c'*64},'intelligence':{'proof_debt':0}}}

def test_evidence_binds_artifacts():
    r=build_release_evidence(bundle(),release_id='r1',commit='abc'); assert r['version']=='29.1.1'; assert verify_release_evidence(r)['valid']

def test_tamper_detected():
    r=build_release_evidence(bundle()); r['certificate']['commit']='tampered'; assert not verify_release_evidence(r)['valid']

def test_property_id_ignores_finding_id():
    a=property_id({'category':'bac','resource':'orders','action':'read','finding_id':'F1'})
    b=property_id({'category':'bac','resource':'orders','action':'read','finding_id':'F999'})
    assert a==b

def test_remediation_contract_is_stable_and_conservative():
    r=build_remediation_contract({'category':'bac','resource':'orders','action':'read','severity':'HIGH','finding_id':'F1'})
    assert r['version']=='29.1.1'; assert r['verification']['missing_evidence']=='BLOCKED'; assert r['verification']['disappeared_observation']=='NOT_RESOLVED'
