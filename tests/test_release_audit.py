from pathlib import Path
from ersec_release_audit import audit

ROOT=Path(__file__).resolve().parents[1]

def test_repository_release_audit_passes():
    r=audit(ROOT)
    assert r['version']=='29.1.0'
    assert r['status']=='PASS', r

def test_audit_is_deterministic():
    a=audit(ROOT); b=audit(ROOT)
    assert a['audit_digest']==b['audit_digest']

def test_audit_is_offline_and_safe():
    r=audit(ROOT)
    assert r['governance']['network_contact'] is False
    assert r['governance']['target_contact'] is False
    assert r['governance']['destructive_actions'] is False
