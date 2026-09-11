from __future__ import annotations

import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ersec.ersec_authorization_benchmark import AuthorizationBenchmarkSuite, CASES  # noqa: E402


@pytest.fixture(scope="module")
def v6_result():
    return AuthorizationBenchmarkSuite.run()


def test_v6_schema_and_truth_separation(v6_result):
    result = v6_result
    assert result["schema"] in {"ersec-authorization-benchmark-suite/2", "ersec-authorization-benchmark-suite/3"}
    assert result["quality"]["truth_mismatches"] == []
    for variant in result["variants"][:2]:
        for row in variant["cases"]:
            assert "ground_truth" in row
            assert "policy_truth" in row


def test_v6_ambiguity_taxonomy_is_explicit():
    reasons = {c.ambiguity_reason for c in CASES if c.truth_class == "ambiguous"}
    assert reasons == {
        "authoritative_response_obscured",
        "field_observation_unavailable",
        "relationship_observer_unavailable",
    }


def test_v6_repeatability_has_three_runs_per_variant(v6_result):
    quality = v6_result["quality"]
    assert all(item["runs"] == 3 for item in quality["replayability"])
    assert quality["replayability_ratio"] == 1.0


def test_v6_request_cost_metrics_are_bounded(v6_result):
    quality = v6_result["quality"]
    assert quality["cost_metrics"]["requests_per_true_positive"] is not None
    assert quality["request_cost_repeats"]["variance_requests"] == 0.0


def test_v6_report_fingerprint_is_sha256(v6_result):
    fingerprint = v6_result["quality"]["benchmark_report_fingerprint"]
    assert len(fingerprint) == 64
    int(fingerprint, 16)
