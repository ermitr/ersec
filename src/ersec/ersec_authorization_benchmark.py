"""Expanded deterministic authorization benchmark corpus for ERSEC.

The suite is deliberately loopback-only and read-only.  It measures ERSEC's
semantic authorization decisions against an operator-reviewed set of secure
expectations, with vulnerable and fixed fixture variants acting as controlled
fault injections.  This module does not claim arbitrary application accuracy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence
import json
import hashlib
import statistics
import time
from pathlib import Path

from ersec.ersec_authorization import json_field_paths
from ersec.ersec_testing import start_multitenant_authorization_fixture
from ersec.ersec_authorization_corpus import build_corpus_manifest, canonical_corpus, family_scorecards, relationship_graph

SUITE_SCHEMA = "ersec-authorization-benchmark-suite/3"


@dataclass(frozen=True)
class SuiteCase:
    case_id: str
    family: str
    identity: str
    path: str
    expected_status: tuple[int, ...]
    forbidden_fields: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    secure_expectation: str = "pass"
    vulnerable_should_violate: bool = False
    truth_class: str = "deterministic"
    oracle_strength: str = "medium"
    relationship: str = "direct"
    expected_owner_tenant: str | None = None
    state_context: str = "steady"
    ambiguity_reason: str | None = None
    policy_truth: str = "reviewed_expectation"

    @property
    def scorable(self) -> bool:
        return self.truth_class in {"vulnerable", "safe"}

    @property
    def key(self) -> str:
        return self.case_id


CASES: tuple[SuiteCase, ...] = (
    SuiteCase("BOLA-ALLOW-001", "horizontal-bola", "tenant_a_user", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("BOLA-DENY-001", "horizontal-bola", "tenant_b_user", "/api/orders/order-tenant-a", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high"),
    SuiteCase("BOLA-DENY-002", "horizontal-bola", "tenant_a_user", "/api/orders/order-tenant-b", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), truth_class="safe", oracle_strength="high"),
    SuiteCase("RBAC-ADMIN-001", "vertical-privilege", "administrator", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("RBAC-USER-001", "vertical-privilege", "tenant_a_user", "/api/admin/summary", (403, 404), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high"),
    SuiteCase("RBAC-B-USER-001", "vertical-privilege", "tenant_b_user", "/api/admin/summary", (403, 404), truth_class="safe", oracle_strength="high"),
    SuiteCase("FIELD-SECRET-001", "field-authorization", "tenant_a_support", "/api/orders/order-tenant-a", (200,), forbidden_fields=("secret_note",), required_fields=("id", "tenant", "amount"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high"),
    SuiteCase("FIELD-OWNER-001", "field-authorization", "tenant_a_user", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high"),
    SuiteCase("ANON-DENY-001", "anonymous-access", "anonymous", "/api/orders/order-tenant-a", (401, 403, 404), truth_class="safe", oracle_strength="high"),
    SuiteCase("REVOKED-SESSION-001", "revoked-session", "revoked_tenant_a_user", "/api/orders/order-tenant-a", (401, 403), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high"),
    SuiteCase("VERSION-DENY-001", "api-version-drift", "tenant_b_user", "/api/v1/orders/order-tenant-a", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high"),
    SuiteCase("VERSION-ALLOW-001", "api-version-drift", "tenant_a_user", "/api/v1/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("VERSION-ALLOW-002", "api-version-drift", "tenant_b_user", "/api/v1/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("VERSION-ADMIN-001", "api-version-drift", "administrator", "/api/v1/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("VERSION-ADMIN-002", "api-version-drift", "administrator", "/api/v1/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("BOLA-ALLOW-002", "horizontal-bola", "tenant_b_user", "/api/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("BOLA-ADMIN-002", "horizontal-bola", "administrator", "/api/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("BOLA-SUPPORT-DENY-001", "horizontal-bola", "tenant_a_support", "/api/orders/order-tenant-b", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), truth_class="safe", oracle_strength="high"),
    SuiteCase("BOLA-ANON-DENY-001", "horizontal-bola", "anonymous", "/api/orders/order-tenant-b", (401, 403, 404), forbidden_fields=("tenant", "amount", "secret_note"), truth_class="safe", oracle_strength="high"),
    SuiteCase("RBAC-SUPPORT-001", "vertical-privilege", "tenant_a_support", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("RBAC-ADMIN-002", "vertical-privilege", "administrator", "/api/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("SAFE-POSITIVE-001", "safe-positive", "tenant_b_user", "/api/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium"),
    SuiteCase("AMBIG-OBSERVER-001", "ambiguous-observation", "tenant_a_user", "/api/orders/order-obscured", (200,), required_fields=("id", "tenant"), truth_class="ambiguous", oracle_strength="low", ambiguity_reason="authoritative_response_obscured"),
    SuiteCase("AMBIG-OBSERVER-002", "ambiguous-observation", "tenant_a_support", "/api/orders/order-obscured", (200,), forbidden_fields=("secret_note",), required_fields=("id",), truth_class="ambiguous", oracle_strength="low", relationship="same_tenant", ambiguity_reason="field_observation_unavailable"),
    SuiteCase("OWNERSHIP-SAME-001", "ownership", "tenant_a_user", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="owner", expected_owner_tenant="tenant_a"),
    SuiteCase("OWNERSHIP-CROSS-001", "ownership", "tenant_b_user", "/api/orders/order-tenant-a", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="cross_tenant", expected_owner_tenant="tenant_a"),
    SuiteCase("OWNERSHIP-ADMIN-001", "ownership", "administrator", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="global_admin", expected_owner_tenant="tenant_a"),
    SuiteCase("ROLE-TENANT-SUPPORT-002", "role-tenant", "tenant_a_support", "/api/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), forbidden_fields=("secret_note",), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="same_tenant_support", expected_owner_tenant="tenant_a"),
    SuiteCase("ROLE-TENANT-SUPPORT-003", "role-tenant", "tenant_a_support", "/api/orders/order-tenant-b", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), truth_class="safe", oracle_strength="high", relationship="cross_tenant_support", expected_owner_tenant="tenant_b"),
    SuiteCase("STALE-AUTH-DENY-001", "stale-authorization", "revoked_tenant_a_user", "/api/orders/order-tenant-a", (401, 403), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="revoked_session", state_context="revoked"),
    SuiteCase("VERSION-DRIFT-SAME-001", "api-version-drift", "tenant_a_user", "/api/v1/orders/order-tenant-a?view=summary", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium", relationship="same_tenant", expected_owner_tenant="tenant_a"),
    SuiteCase("VERSION-DRIFT-CROSS-001", "api-version-drift", "tenant_b_user", "/api/v1/orders/order-tenant-a?view=summary", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="cross_tenant", expected_owner_tenant="tenant_a"),
    SuiteCase("AMBIG-RELATIONSHIP-001", "ambiguous-relationship", "tenant_a_user", "/api/orders/order-obscured", (200,), required_fields=("id",), truth_class="ambiguous", oracle_strength="low", relationship="unknown", state_context="observer_unavailable", ambiguity_reason="relationship_observer_unavailable"),
    # Expanded corpus v5: repeated relationship dimensions across stable endpoints.
    SuiteCase("REL-OWNER-A-001", "relationship-coverage", "tenant_a_user", "/api/v1/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="owner", expected_owner_tenant="tenant_a"),
    SuiteCase("REL-OWNER-B-001", "relationship-coverage", "tenant_b_user", "/api/v1/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="owner", expected_owner_tenant="tenant_b"),
    SuiteCase("REL-CROSS-A-001", "relationship-coverage", "tenant_b_user", "/api/v1/orders/order-tenant-a", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="cross_tenant", expected_owner_tenant="tenant_a"),
    SuiteCase("REL-CROSS-B-001", "relationship-coverage", "tenant_a_user", "/api/v1/orders/order-tenant-b", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), truth_class="safe", oracle_strength="high", relationship="cross_tenant", expected_owner_tenant="tenant_b"),
    SuiteCase("REL-SUPPORT-A-001", "relationship-coverage", "tenant_a_support", "/api/v1/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), forbidden_fields=("secret_note",), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="same_tenant_support", expected_owner_tenant="tenant_a"),
    SuiteCase("REL-SUPPORT-B-001", "relationship-coverage", "tenant_b_user", "/api/v1/orders/order-tenant-b?view=summary", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="medium", relationship="same_tenant", expected_owner_tenant="tenant_b"),
    SuiteCase("REL-ADMIN-A-001", "relationship-coverage", "administrator", "/api/v1/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="global_admin", expected_owner_tenant="tenant_a"),
    SuiteCase("REL-ADMIN-B-001", "relationship-coverage", "administrator", "/api/v1/orders/order-tenant-b", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="global_admin", expected_owner_tenant="tenant_b"),
    SuiteCase("DRIFT-QUERY-A-001", "api-version-drift", "tenant_a_user", "/api/v1/orders/order-tenant-a?view=summary", (200,), required_fields=("id", "tenant", "amount"), truth_class="safe", oracle_strength="high", relationship="same_tenant", expected_owner_tenant="tenant_a"),
    SuiteCase("DRIFT-QUERY-B-001", "api-version-drift", "tenant_b_user", "/api/v1/orders/order-tenant-a?view=summary", (403, 404), forbidden_fields=("tenant", "amount", "secret_note"), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="cross_tenant", expected_owner_tenant="tenant_a"),
    SuiteCase("FIELD-SAFE-SUPPORT-B-001", "field-authorization", "tenant_a_support", "/api/v1/orders/order-tenant-a", (200,), required_fields=("id", "tenant", "amount"), forbidden_fields=("secret_note",), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="same_tenant_support", expected_owner_tenant="tenant_a"),
    SuiteCase("FIELD-VULN-SUPPORT-A-001", "field-authorization", "tenant_a_support", "/api/v1/orders/order-tenant-a?view=summary", (200,), required_fields=("id", "tenant", "amount"), forbidden_fields=("secret_note",), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="same_tenant_support", expected_owner_tenant="tenant_a"),
    SuiteCase("VERTICAL-ANON-001", "vertical-privilege", "anonymous", "/api/admin/summary", (401, 403, 404), truth_class="safe", oracle_strength="high", relationship="anonymous", state_context="unauthenticated"),
    SuiteCase("VERTICAL-SUPPORT-001", "vertical-privilege", "tenant_a_support", "/api/admin/summary", (403, 404), truth_class="safe", oracle_strength="high", relationship="same_tenant_support"),
    SuiteCase("REVOKED-RESTORE-001", "stale-authorization", "revoked_tenant_a_user", "/api/v1/orders/order-tenant-a", (401, 403), vulnerable_should_violate=True, truth_class="vulnerable", oracle_strength="high", relationship="revoked_session", state_context="revoked"),
)


class AuthorizationBenchmarkSuite:
    """Run the operator-reviewed benchmark suite against local fixtures."""

    @staticmethod
    def _fixture_request(fixture, case: SuiteCase, *, vulnerable: bool) -> Dict[str, Any]:
        from ersec import ScanConfig, SafeHttpClient
        cfg = ScanConfig(target=fixture.base_url)
        host = fixture.base_url.split("://", 1)[1].rsplit(":", 1)[0]
        port = int(fixture.base_url.rsplit(":", 1)[1])
        cfg.scope.allowed_hosts = [host]
        cfg.scope.allowed_ports = [port]
        cfg.scope.allow_private_addresses = True
        cfg.scope.allowed_methods = ["GET"]
        cfg.scope.max_requests = 100
        cfg.timeout_seconds = 2.0
        client = SafeHttpClient(cfg)
        url = fixture.base_url + case.path
        try:
            response = client.request("GET", url, headers={"X-ERSEC-Identity": case.identity})
            try:
                payload = response.json()
            except Exception:
                payload = None
            fields = json_field_paths(payload) if isinstance(payload, (dict, list)) else []
            return {
                "case_id": case.case_id,
                "family": case.family,
                "identity": case.identity,
                "url": url,
                "method": "GET",
                "status": response.status_code,
                "observed_fields": fields,
                "secure_expectation": case.secure_expectation,
                "vulnerable_variant": vulnerable,
            }
        except Exception as exc:
            return {
                "case_id": case.case_id,
                "family": case.family,
                "identity": case.identity,
                "url": url,
                "method": "GET",
                "verdict": "inconclusive",
                "error": str(exc),
                "secure_expectation": case.secure_expectation,
                "vulnerable_variant": vulnerable,
            }
        finally:
            client.close()

    @classmethod
    def run_variant(cls, *, vulnerable: bool, cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        fixture = start_multitenant_authorization_fixture(vulnerable=vulnerable)
        started = time.perf_counter()
        rows: List[Dict[str, Any]] = []
        try:
            for case in cases:
                rows.append(cls._fixture_request(fixture, case, vulnerable=vulnerable))
        finally:
            fixture.close()
        runtime = time.perf_counter() - started
        lifecycle = fixture.lifecycle_status()
        verdict_rows: List[Dict[str, Any]] = []
        for case, row in zip(cases, rows):
            if row.get("verdict") == "inconclusive":
                verdict_rows.append({**row, "verdict": "inconclusive", "ground_truth": cls._ground_truth(case, vulnerable=vulnerable), "policy_truth": case.policy_truth, "ambiguity_reason": case.ambiguity_reason})
                continue
            status = row.get("status")
            if case.truth_class == "ambiguous":
                paths = row.get("observed_fields", [])
                verdict = "observation_unavailable" if not paths else "inconclusive"
                reason = "authoritative semantic observation was intentionally unavailable in this fixture"
            elif status not in case.expected_status:
                verdict = "violation"
                reason = f"observed HTTP status {status!r} is outside expected secure status set"
            else:
                paths = row.get("observed_fields", [])
                forbidden = [f for f in case.forbidden_fields if any(p == f or p.startswith(f + ".") for p in paths)]
                required_missing = [f for f in case.required_fields if not any(p == f or p.startswith(f + ".") for p in paths)]
                if forbidden:
                    verdict = "violation"
                    reason = "forbidden response fields were observable"
                elif required_missing:
                    verdict = "observation_unavailable" if not paths else "violation"
                    reason = "required response fields were not observable"
                else:
                    verdict = "pass"
                    reason = "secure expectation matched observed behavior"
            verdict_rows.append({**row, "verdict": verdict, "ground_truth": cls._ground_truth(case, vulnerable=vulnerable), "policy_truth": case.policy_truth, "ambiguity_reason": case.ambiguity_reason, "truth_class": case.truth_class, "relationship": case.relationship})
        counts = {v: sum(1 for r in verdict_rows if r.get("verdict") == v) for v in ("pass", "violation", "inconclusive", "observation_unavailable")}
        unexpected_uncertainty = any(
            r.get("verdict") in {"inconclusive", "observation_unavailable"} and next(c for c in cases if c.case_id == r.get("case_id")).truth_class != "ambiguous"
            for r in verdict_rows
        )
        return {
            "name": "vulnerable" if vulnerable else "fixed",
            "status": "fail" if counts["violation"] and any(
                next(c for c in cases if c.case_id == r.get("case_id")).truth_class != "ambiguous"
                for r in verdict_rows if r.get("verdict") == "violation"
            ) else ("inconclusive" if (counts["inconclusive"] or unexpected_uncertainty) else "pass"),
            "request_count": len(verdict_rows),
            "runtime_seconds": round(runtime, 6),
            "counts": counts,
            "cases": verdict_rows,
            "fixture_lifecycle": lifecycle,
        }

    @staticmethod
    def _ground_truth(case: SuiteCase, *, vulnerable: bool) -> str:
        """Return reviewed policy truth independently from observed detector verdict."""
        if case.truth_class == "ambiguous":
            return "ambiguous"
        if vulnerable and case.vulnerable_should_violate:
            return "violation"
        return "pass"

    @staticmethod
    def _variance(values: Sequence[float]) -> float:
        return round(statistics.pvariance(values), 9) if len(values) > 1 else 0.0

    @classmethod
    def score(cls, runs: Sequence[Mapping[str, Any]], cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        expected_positive = {c.case_id for c in cases if c.vulnerable_should_violate and c.truth_class == "vulnerable"}
        ambiguous_ids = {c.case_id for c in cases if c.truth_class == "ambiguous"}
        scorable_ids = {c.case_id for c in cases if c.scorable}
        vulnerable = next(r for r in runs if r.get("name") == "vulnerable")
        fixed = next(r for r in runs if r.get("name") == "fixed")
        observed_vulnerable = {str(r.get("case_id")) for r in vulnerable.get("cases", []) if r.get("verdict") == "violation" and str(r.get("case_id")) in scorable_ids}
        observed_fixed = {str(r.get("case_id")) for r in fixed.get("cases", []) if r.get("verdict") == "violation" and str(r.get("case_id")) in scorable_ids}
        tp = len(expected_positive & observed_vulnerable)
        fp = len(observed_vulnerable - expected_positive)
        fn = len(expected_positive - observed_vulnerable)
        observed_truth_mismatches = []
        for run in (vulnerable, fixed):
            for row in run.get("cases", []):
                case = next((c for c in cases if c.case_id == row.get("case_id")), None)
                if case is None or not case.scorable:
                    continue
                truth = cls._ground_truth(case, vulnerable=(run.get("name") == "vulnerable"))
                observed = str(row.get("verdict", ""))
                if observed not in {truth}:
                    observed_truth_mismatches.append({"variant": run.get("name"), "case_id": case.case_id, "expected": truth, "observed": observed})
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        families: Dict[str, Dict[str, Any]] = {}
        for case in cases:
            fam = families.setdefault(case.family, {"applicable": 0, "scorable": 0, "ambiguous": 0, "vulnerable_violations": 0, "fixed_violations": 0})
            fam["applicable"] += 1
            if case.scorable:
                fam["scorable"] += 1
            else:
                fam["ambiguous"] += 1
            if case.case_id in observed_vulnerable:
                fam["vulnerable_violations"] += 1
            if case.case_id in observed_fixed:
                fam["fixed_violations"] += 1
        all_observed_ids = {str(r.get("case_id")) for variant in (vulnerable, fixed) for r in variant.get("cases", []) if r.get("case_id")}
        observed_scorable = scorable_ids & all_observed_ids
        family_metrics: Dict[str, Dict[str, Any]] = {}
        for family_name, fam in families.items():
            expected = {c.case_id for c in cases if c.family == family_name and c.scorable and c.vulnerable_should_violate}
            observed = {cid for cid in observed_vulnerable if cid in {c.case_id for c in cases if c.family == family_name}}
            tp_f = len(expected & observed)
            fp_f = len(observed - expected)
            fn_f = len(expected - observed)
            p_f = tp_f / (tp_f + fp_f) if tp_f + fp_f else 1.0
            r_f = tp_f / (tp_f + fn_f) if tp_f + fn_f else 1.0
            f_f = (2*p_f*r_f/(p_f+r_f)) if p_f+r_f else 0.0
            family_metrics[family_name] = {
                "true_positives": tp_f, "false_positives": fp_f, "false_negatives": fn_f,
                "precision": round(p_f, 4), "recall": round(r_f, 4), "f1": round(f_f, 4),
            }
        family_observed: Dict[str, Dict[str, Any]] = {}
        for case in cases:
            item = family_observed.setdefault(case.family, {"applicable": 0, "observed": 0, "scorable": 0})
            item["applicable"] += 1
            if case.scorable:
                item["scorable"] += 1
            if case.case_id in all_observed_ids:
                item["observed"] += 1
        for fam, item in family_observed.items():
            denom = item["applicable"]
            item["coverage_ratio"] = round(item["observed"] / denom, 4) if denom else 1.0
        relationship_coverage: Dict[str, Dict[str, Any]] = {}
        for case in cases:
            item = relationship_coverage.setdefault(case.relationship, {"applicable": 0, "scorable": 0, "observed": 0})
            item["applicable"] += 1
            if case.scorable:
                item["scorable"] += 1
            if any(str(r.get("case_id")) == case.case_id for r in vulnerable.get("cases", [])):
                item["observed"] += 1
        for item in relationship_coverage.values():
            item["coverage_ratio"] = round(item["observed"] / item["applicable"], 4) if item["applicable"] else 1.0
        requests_total = sum(int(r.get("request_count", 0)) for r in runs)
        runtime_samples = [float(r.get("runtime_seconds", 0.0)) for r in runs]
        cost_metrics = {
            "requests_total": requests_total,
            "requests_per_scorable_case": round(requests_total / len(scorable_ids), 4) if scorable_ids else 0.0,
            "runtime_mean_seconds": round(statistics.mean(runtime_samples), 6) if runtime_samples else 0.0,
            "runtime_max_seconds": round(max(runtime_samples), 6) if runtime_samples else 0.0,
        }
        true_positive_denominator = tp
        requests_per_true_positive = (requests_total / true_positive_denominator) if true_positive_denominator else None
        family_metrics_cost = {}
        for family_name, fm in family_metrics.items():
            family_tp = fm["true_positives"]
            family_case_ids = {c.case_id for c in cases if c.family == family_name}
            family_metric_cost = sum(
                int(r.get("request_count", 0))
                for r in (vulnerable, fixed)
                if any(str(item.get("case_id")) in family_case_ids for item in r.get("cases", []) if isinstance(item, Mapping))
            )
            family_metrics_cost[family_name] = {"requests_observed": family_metric_cost, "requests_per_true_positive": round(family_metric_cost / family_tp, 4) if family_tp else None}
        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "truth_mismatches": observed_truth_mismatches,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "scorable_case_coverage_ratio": round(len(observed_scorable) / len(scorable_ids), 4) if scorable_ids else 0.0,
            "corpus_case_count": len(cases),
            "ambiguous_case_count": len(ambiguous_ids),
            "truth_classes": {"scorable": len(scorable_ids), "ambiguous": len(ambiguous_ids)},
            "expected_vulnerable_cases": sorted(expected_positive),
            "observed_vulnerable_cases": sorted(observed_vulnerable),
            "observed_fixed_violations": sorted(observed_fixed),
            "fixed_variant_safe": not observed_fixed,
            "families": families,
            "family_metrics": family_metrics,
            "family_coverage": family_observed,
            "relationship_coverage": relationship_coverage,
            "cost_metrics": {**cost_metrics, "requests_per_true_positive": round(requests_per_true_positive, 4) if requests_per_true_positive is not None else None},
            "family_cost_metrics": family_metrics_cost,
            "requests_total": requests_total,
            "requests_per_scorable_case": round(requests_total / len(scorable_ids), 4) if scorable_ids else 0.0,
        }

    @staticmethod
    def _case_signature(run: Mapping[str, Any]) -> Dict[str, str]:
        return {str(item.get("case_id")): str(item.get("verdict")) for item in run.get("cases", []) if isinstance(item, Mapping)}

    @classmethod
    def run(cls, cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        initial = [cls.run_variant(vulnerable=True, cases=cases), cls.run_variant(vulnerable=False, cases=cases)]
        replays = [cls.run_variant(vulnerable=True, cases=cases), cls.run_variant(vulnerable=False, cases=cases), cls.run_variant(vulnerable=True, cases=cases), cls.run_variant(vulnerable=False, cases=cases)]
        quality = cls.score(initial, cases)
        corpus_errors = []
        seen_ids = set()
        for case in cases:
            if case.case_id in seen_ids:
                corpus_errors.append(f"duplicate case id: {case.case_id}")
            seen_ids.add(case.case_id)
            if not case.family or not case.path.startswith("/"):
                corpus_errors.append(f"invalid case metadata: {case.case_id}")
            if case.truth_class not in {"vulnerable", "safe", "ambiguous"}:
                corpus_errors.append(f"unsupported truth class: {case.case_id}")
            if case.truth_class == "ambiguous" and not case.ambiguity_reason:
                corpus_errors.append(f"ambiguous case missing ambiguity_reason: {case.case_id}")
            if case.policy_truth != "reviewed_expectation":
                corpus_errors.append(f"unsupported policy_truth: {case.case_id}")
        replayability = []
        grouped: Dict[str, List[Mapping[str, Any]]] = {"vulnerable": [], "fixed": []}
        grouped["vulnerable"].append(initial[0])
        grouped["fixed"].append(initial[1])
        for run in replays:
            grouped[run["name"]].append(run)
        for variant_name, runs_for_variant in grouped.items():
            signatures = [cls._case_signature(r) for r in runs_for_variant]
            ids = sorted(set().union(*(set(sig) for sig in signatures))) if signatures else []
            stable = sum(1 for case_id in ids if len({sig.get(case_id) for sig in signatures}) == 1)
            replayability.append({
                "variant": variant_name,
                "runs": len(signatures),
                "cases_compared": len(ids),
                "stable_cases": stable,
                "ratio": round(stable / len(ids), 4) if ids else 1.0,
                "deterministic_case_verdicts": all(sig == signatures[0] for sig in signatures[1:]) if signatures else True,
            })
        quality["replayability"] = replayability
        quality["replayability_ratio"] = min((item["ratio"] for item in replayability), default=1.0)
        runtime_samples = [float(r.get("runtime_seconds", 0.0)) for r in initial + replays]
        request_samples = [int(r.get("request_count", 0)) for r in initial + replays]
        quality["runtime"] = {
            "samples": [round(x, 6) for x in runtime_samples],
            "mean_seconds": round(statistics.mean(runtime_samples), 6) if runtime_samples else 0.0,
            "max_seconds": round(max(runtime_samples), 6) if runtime_samples else 0.0,
            "variance_seconds": cls._variance(runtime_samples),
        }
        quality["request_cost_repeats"] = {
            "samples": request_samples,
            "mean_requests": round(statistics.mean(request_samples), 4) if request_samples else 0.0,
            "variance_requests": cls._variance([float(x) for x in request_samples]),
            "max_requests": max(request_samples) if request_samples else 0,
        }
        quality["fixture_lifecycle"] = {
            "loopback_only": True,
            "state_changes": False,
            "cleanup_verified": all(bool(r.get("fixture_lifecycle", {}).get("cleanup_verified")) for r in initial + replays),
            "residual_objects": sum(int(r.get("fixture_lifecycle", {}).get("residual_objects", 0)) for r in initial + replays),
            "shutdown_observed": all(bool(r.get("fixture_lifecycle", {}).get("closed")) for r in initial + replays),
        }
        corpus_digest = hashlib.sha256(json.dumps([
            {"id": c.case_id, "family": c.family, "identity": c.identity, "path": c.path,
             "truth_class": c.truth_class, "expected_status": list(c.expected_status),
             "forbidden_fields": list(c.forbidden_fields), "required_fields": list(c.required_fields), "relationship": c.relationship, "expected_owner_tenant": c.expected_owner_tenant, "state_context": c.state_context, "ambiguity_reason": c.ambiguity_reason, "policy_truth": c.policy_truth}
            for c in cases
        ], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        quality["corpus_validation"] = {"valid": not corpus_errors, "errors": corpus_errors, "corpus_digest": corpus_digest}
        quality["family_scorecards"] = family_scorecards(cases, {"cases": initial[0].get("cases", [])})
        quality["relationship_graph"] = relationship_graph(cases)
        quality["canonical_corpus"] = canonical_corpus(cases)
        quality["benchmark_report_fingerprint"] = hashlib.sha256(
            json.dumps({"schema": SUITE_SCHEMA, "benchmark_id": "multitenant-authorization-suite-v7", "corpus_digest": corpus_digest, "quality": {k: quality[k] for k in ("precision", "recall", "f1", "true_positives", "false_positives", "false_negatives", "replayability_ratio")} }, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        ambiguous_case_count = sum(1 for c in cases if c.truth_class == "ambiguous")
        quality["dimension_coverage"] = {
            "api_versions": sorted({"v2" if "/api/v2/" in c.path else "v1" if "/api/v1/" in c.path else "legacy" for c in cases}),
            "relationships": sorted({c.relationship for c in cases}),
            "field_policy_cases": sum(1 for c in cases if c.forbidden_fields or c.required_fields),
            "state_contexts": sorted({c.state_context for c in cases}),
            "truth_class_counts": {k: sum(1 for c in cases if c.truth_class == k) for k in ("vulnerable","safe","ambiguous")},
        }
        pass_condition = (
            quality["false_positives"] == 0
            and quality["false_negatives"] == 0
            and quality["fixed_variant_safe"]
            and quality["replayability_ratio"] == 1.0
            and quality["scorable_case_coverage_ratio"] == 1.0
            and quality["corpus_validation"]["valid"]
            and quality["fixture_lifecycle"]["cleanup_verified"]
            and quality["fixture_lifecycle"]["residual_objects"] == 0
            and any(r.get("name") == "vulnerable" and r.get("status") == "fail" for r in initial)
            and any(r.get("name") == "fixed" and r.get("status") == "pass" for r in initial)
            and all(r.get("counts", {}).get("observation_unavailable", 0) == ambiguous_case_count for r in initial)
        )
        return {
            "schema": SUITE_SCHEMA,
            "benchmark_id": "multitenant-authorization-suite-v7",
            "status": "pass" if pass_condition else "fail",
            "case_count": len(cases),
            "cases": [
                {"id": c.case_id, "family": c.family, "identity": c.identity, "path": c.path,
                 "expected_status": list(c.expected_status), "forbidden_fields": list(c.forbidden_fields),
                 "required_fields": list(c.required_fields), "truth_class": c.truth_class,
                 "oracle_strength": c.oracle_strength, "ambiguity_reason": c.ambiguity_reason,
                 "policy_truth": c.policy_truth, "vulnerable_should_violate": c.vulnerable_should_violate,
                 "benchmark_dimensions": {
                     "relationship": c.relationship,
                     "api_version": "v2" if "/api/v2/" in c.path else "v1" if "/api/v1/" in c.path else "legacy",
                     "field_policy": bool(c.forbidden_fields or c.required_fields),
                     "state_context": c.state_context,
                 }}
                for c in cases
            ],
            "variants": list(initial),
            "quality": quality,
            "methodology": {
                "version": 2,
                "policy_truth_and_detector_truth": "reviewed ground truth is explicit and separate from observed detector verdicts",
                "repeat_runs": 3,
                "ground_truth": "operator-reviewed secure expectation with controlled fault injection and explicit ambiguity cases",
                "targets": "loopback-only synthetic application",
                "methods": ["GET"],
                "state_changes": False,
                "credential_values_captured": False,
                "denominator": f"{len(cases)} explicit cases; ambiguous cases are reported and excluded from precision/recall",
                "truth_classes": {"vulnerable": sum(1 for c in cases if c.truth_class == "vulnerable"), "safe": sum(1 for c in cases if c.truth_class == "safe"), "ambiguous": sum(1 for c in cases if c.truth_class == "ambiguous")},
                "policy_truth_source": "operator_reviewed_expected_behavior is stored separately from observed verdicts",
                "ambiguity_taxonomy": sorted({c.ambiguity_reason for c in cases if c.ambiguity_reason}),
                "repetitions": 3,
                "comparison_scope": "This result is only for the included deterministic corpus; it is not a competitor benchmark.",
                "relationship_dimensions": sorted({c.relationship for c in cases}),
                "cost_measurement": "requests and runtime are measured for vulnerable and fixed variants; no extrapolation is implied.",
                "corpus_manifest": build_corpus_manifest(cases, benchmark_id="multitenant-authorization-suite-v7"),
            },
        }

    @classmethod
    def write(cls, path: str, cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        result = cls.run(cases)
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result
