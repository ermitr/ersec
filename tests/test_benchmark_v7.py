from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from ersec.ersec_authorization_benchmark import AuthorizationBenchmarkSuite

def test_v7_schema_and_dimensions():
    r=AuthorizationBenchmarkSuite.run()
    assert r["schema"] == "ersec-authorization-benchmark-suite/3"
    assert r["status"] == "pass"
    assert r["quality"]["truth_mismatches"] == []
    assert r["quality"]["dimension_coverage"]["field_policy_cases"] > 0
    assert "relationships" in r["quality"]["dimension_coverage"]

def test_v7_external_comparison_manifest_is_reproducible():
    r=AuthorizationBenchmarkSuite.run()
    manifest=r["methodology"]["corpus_manifest"]
    assert manifest["benchmark_id"] == "multitenant-authorization-suite-v7"
    assert len(manifest["corpus_digest"]) == 64
