from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ersec_research_benchmark import ResearchAuthorizationBenchmark, canonicalize_query


def test_research_benchmark_separates_truth_and_detector_results():
    result = ResearchAuthorizationBenchmark.run()
    assert result["status"] == "pass"
    assert result["error_analysis"]["error_count"] == 0
    assert result["benchmark"]["methodology"]["ground_truth"]


def test_comparison_manifest_has_stable_rules():
    result = ResearchAuthorizationBenchmark.run()
    manifest = result["comparison_manifest"]
    assert manifest["comparison_rules"]["same_corpus"] is True
    assert manifest["comparison_rules"]["report_false_positives_and_false_negatives"] is True
    assert len(manifest["manifest_digest"]) == 64


def test_query_order_metamorphic_canonicalization():
    a = canonicalize_query("https://example.test/api/orders?b=2&a=1")
    b = canonicalize_query("https://example.test/api/orders?a=1&b=2")
    assert a == b
