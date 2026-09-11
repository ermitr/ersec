import tempfile
from pathlib import Path
from ersec.ersec_roadmap_audit import audit

def _tree():
    root = Path(tempfile.mkdtemp())
    for name in ["ersec_assurance_compiler.py", "tests/test_assurance_compiler.py", "examples/security-behavior-policy-29.1.1.yaml"]:
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("x", encoding="utf-8")
    return root

def test_partial_audit_is_honest():
    result = audit(_tree())
    assert result["version"] == "29.1.1"
    assert result["status"] == "PARTIAL"
    assert result["covered_features"] == 1
    assert result["explicit_remaining_gaps"]

def test_real_tree_has_all_feature_anchors():
    result = audit(Path(__file__).resolve().parents[1])
    assert result["feature_count"] == 10
    assert result["covered_features"] == 10
    assert result["status"] == "PASS"  # all 29.1.1 engineering roadmap anchors are implemented; external execution is an explicit validation gate
    assert result["explicit_remaining_gaps"] == []
    assert result["audit_digest"] == audit(Path(__file__).resolve().parents[1])["audit_digest"]
