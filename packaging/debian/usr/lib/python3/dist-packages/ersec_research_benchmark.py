"""Research-grade authorization benchmark analysis for ERSEC.

This module does not execute arbitrary external targets. It analyzes the
operator-reviewed deterministic authorization benchmark and produces a
comparison-ready manifest plus error/coverage analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
import hashlib
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ersec_authorization_benchmark import CASES, AuthorizationBenchmarkSuite

SCHEMA = "ersec-authorization-research/1"


@dataclass(frozen=True)
class MetricDefinition:
    name: str
    definition: str
    denominator: str


METRICS = (
    MetricDefinition("precision", "true positives / (true positives + false positives)", "scorable positive observations"),
    MetricDefinition("recall", "true positives / (true positives + false negatives)", "reviewed vulnerable cases expected to violate"),
    MetricDefinition("f1", "harmonic mean of precision and recall", "precision and recall"),
    MetricDefinition("case_coverage", "observed case IDs / applicable case IDs", "all declared cases"),
    MetricDefinition("requests_per_true_positive", "total benchmark requests / true positives", "observed true positives"),
    MetricDefinition("replayability", "identical verdict signatures across repeated runs", "cases compared across repetitions"),
)


def _fingerprint(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def canonicalize_query(url: str) -> str:
    """Normalize query ordering without changing values or fragments."""
    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def metamorphic_case_checks(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Run deterministic metamorphic checks on captured benchmark records.

    These are representation-level invariants: fragment changes must not alter
    request identity, and reordering equivalent query parameters must preserve
    their canonical semantic URL. They do not contact a target.
    """
    checks: list[dict[str, Any]] = []
    for row in rows:
        url = str(row.get("url", ""))
        if not url:
            continue
        parts = urlsplit(url)
        with_fragment = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "section"))
        fragment_removed = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        checks.append({
            "case_id": row.get("case_id"),
            "fragment_invariant": canonicalize_query(with_fragment) == fragment_removed,
            "query_canonical": canonicalize_query(url),
        })
    return checks


def _case_index() -> dict[str, Any]:
    return {c.case_id: c for c in CASES}


def error_analysis(result: Mapping[str, Any]) -> dict[str, Any]:
    """Produce explicit false-positive/negative and uncertainty analysis."""
    case_index = _case_index()
    variants = {str(v.get("name")): v for v in result.get("variants", []) if isinstance(v, Mapping)}
    vulnerable = variants.get("vulnerable", {})
    fixed = variants.get("fixed", {})
    rows_v = [r for r in vulnerable.get("cases", []) if isinstance(r, Mapping)]
    rows_f = [r for r in fixed.get("cases", []) if isinstance(r, Mapping)]
    by_v = {str(r.get("case_id")): r for r in rows_v}
    by_f = {str(r.get("case_id")): r for r in rows_f}
    errors: list[dict[str, Any]] = []
    for case_id, case in case_index.items():
        if not case.scorable:
            continue
        expected_v = "violation" if case.vulnerable_should_violate else "pass"
        actual_v = str(by_v.get(case_id, {}).get("verdict", "missing"))
        expected_f = "pass"
        actual_f = str(by_f.get(case_id, {}).get("verdict", "missing"))
        if actual_v != expected_v:
            errors.append({"variant": "vulnerable", "case_id": case_id, "type": "false_negative_or_misclassification", "expected": expected_v, "observed": actual_v, "family": case.family, "relationship": case.relationship})
        if actual_f != expected_f:
            errors.append({"variant": "fixed", "case_id": case_id, "type": "false_positive_or_misclassification", "expected": expected_f, "observed": actual_f, "family": case.family, "relationship": case.relationship})
    uncertainty = []
    for variant_name, rows in (("vulnerable", rows_v), ("fixed", rows_f)):
        for row in rows:
            verdict = str(row.get("verdict", ""))
            case = case_index.get(str(row.get("case_id")))
            if case and verdict in {"inconclusive", "observation_unavailable"}:
                uncertainty.append({
                    "variant": variant_name,
                    "case_id": case.case_id,
                    "family": case.family,
                    "reason": row.get("ambiguity_reason") or case.ambiguity_reason or "unspecified",
                    "verdict": verdict,
                })
    return {"errors": errors, "uncertainty": uncertainty, "error_count": len(errors), "uncertainty_count": len(uncertainty)}


def build_comparison_manifest(result: Mapping[str, Any]) -> dict[str, Any]:
    methodology = result.get("methodology", {}) if isinstance(result.get("methodology"), Mapping) else {}
    corpus_manifest = methodology.get("corpus_manifest", {}) if isinstance(methodology.get("corpus_manifest"), Mapping) else {}
    manifest = {
        "schema": "ersec-benchmark-comparison-manifest/1",
        "benchmark_id": result.get("benchmark_id"),
        "benchmark_schema": result.get("schema"),
        "corpus_digest": corpus_manifest.get("corpus_digest"),
        "case_count": result.get("case_count"),
        "methodology_version": methodology.get("version"),
        "scope": {
            "targets": "loopback-only synthetic application",
            "methods": ["GET"],
            "state_changes": False,
            "external_targets": False,
            "credential_values_captured": False,
        },
        "truth": {
            "source": "operator_reviewed_expected_behavior",
            "detector_truth_separate": True,
            "ambiguous_cases_excluded_from_precision_recall": True,
        },
        "metrics": [m.__dict__ for m in METRICS],
        "comparison_rules": {
            "same_corpus": True,
            "same_target_variant": True,
            "same_truth_labels": True,
            "report_false_positives_and_false_negatives": True,
            "report_unavailable_and_not_tested": True,
            "do_not_compare_alert_counts_as_effectiveness": True,
            "no_external_network_access": True,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    manifest["manifest_digest"] = _fingerprint({k: v for k, v in manifest.items() if k != "manifest_digest"})
    return manifest


class ResearchAuthorizationBenchmark:
    """Compatibility wrapper exposed through the ERSEC CLI."""

    run = staticmethod(lambda: run())
    write = staticmethod(lambda path: write(path))


def run() -> dict[str, Any]:
    suite = AuthorizationBenchmarkSuite.run()
    analysis = error_analysis(suite)
    rows = []
    for variant in suite.get("variants", []):
        rows.extend(variant.get("cases", []))
    metamorphic = metamorphic_case_checks([r for r in rows if isinstance(r, Mapping)])
    comparison = build_comparison_manifest(suite)
    return {
        "schema": SCHEMA,
        "benchmark": suite,
        "comparison_manifest": comparison,
        "error_analysis": analysis,
        "metamorphic": {
            "checks": len(metamorphic),
            "passed": sum(1 for c in metamorphic if c.get("fragment_invariant")),
            "failed": sum(1 for c in metamorphic if not c.get("fragment_invariant")),
            "results": metamorphic,
        },
        "status": "pass" if suite.get("status") == "pass" and not analysis["errors"] and all(c.get("fragment_invariant") for c in metamorphic) else "fail",
    }


def write(path: str) -> dict[str, Any]:
    result = run()
    out = open(path, "w", encoding="utf-8")
    try:
        json.dump(result, out, indent=2, sort_keys=True)
        out.write("\n")
    finally:
        out.close()
    return result
