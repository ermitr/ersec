import json
from ersec_assurance_benchmark_lab import AssuranceBenchmarkLab, split_corpus
from ersec_authorization_benchmark import CASES


def test_deterministic_split_and_nonempty_tiers():
    a = split_corpus(CASES)
    b = split_corpus(CASES)
    assert {k: [c.case_id for c in v] for k, v in a.items()} == {k: [c.case_id for c in v] for k, v in b.items()}
    assert all(a[k] for k in ("public", "release", "held_out"))
    assert len({c.case_id for v in a.values() for c in v}) == len(CASES)


def test_lab_produces_reproducible_evidence_contract():
    result = AssuranceBenchmarkLab.run(CASES[:8])
    assert result["version"] == "29.1.0"
    assert result["status"] in {"pass", "fail"}
    assert result["corpus"]["case_count"] == 8
    assert len(result["reproducibility_digest"]) == 64
    assert result["observer_conflict_probe"]["status"] == "inconclusive"
    assert result["methodology"]["network_contact"] is False
    assert result["methodology"]["destructive_actions"] is False
    assert len(result["evidence_contract"]) >= 10
