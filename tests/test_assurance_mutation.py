from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ersec.ersec_assurance_mutation import AuthorizationMutationAudit, generate_mutants


def test_mutation_audit_is_bounded_and_offline():
    result = AuthorizationMutationAudit.run()
    assert result["schema"] == "ersec-authorization-mutation-audit/1"
    assert result["methodology"]["not_a_detection_metric"] is True
    assert result["summary"]["generated"] >= 20
    assert len(result["audit_digest"]) == 64


def test_mutation_operators_cover_core_security_dimensions():
    ops = {m.operator for m in generate_mutants()}
    assert {"outcome-flip", "field-allow", "relationship-swap", "revocation-erase", "version-erase"} <= ops


def test_mutation_audit_never_contacts_network():
    result = AuthorizationMutationAudit.run()
    assert result["methodology"]["execution"] == "offline/static; no target contact"
