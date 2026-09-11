"""Reproducible, loopback-only authorization benchmark laboratory.

This module provides a small deterministic ground-truth benchmark for ERSEC's
semantic authorization wedge. It is intentionally local, bounded, and safe:
no external target is contacted and no state-changing request is generated.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping

from ersec_authorization import AuthorizationAssuranceEngine, json_field_paths
from ersec_behavior import SecurityBehaviorModel
from ersec_testing import start_multitenant_authorization_fixture

AUTHZ_BENCHMARK_SCHEMA = "ersec-authorization-benchmark/1"


@dataclass(frozen=True)
class BenchmarkRun:
    variant: str
    status: str
    report: Dict[str, Any]
    runtime_seconds: float
    request_count: int


class AuthorizationBenchmarkLab:
    """Execute the deterministic multi-tenant authorization benchmark."""

    @staticmethod
    def _model(base_url: str) -> SecurityBehaviorModel:
        return SecurityBehaviorModel(
            {
                "schema": "ersec-security-behavior-model/1",
                "version": 1,
                "name": "ERSEC benchmark: multitenant-rest",
                "identities": [
                    {"name": "anonymous", "role": "anonymous", "tenant": "", "privilege_rank": 0},
                    {"name": "tenant_a_user", "role": "user", "tenant": "tenant_a", "privilege_rank": 1},
                    {"name": "tenant_a_support", "role": "support", "tenant": "tenant_a", "privilege_rank": 1},
                    {"name": "tenant_b_user", "role": "user", "tenant": "tenant_b", "privilege_rank": 1},
                    {"name": "administrator", "role": "admin", "tenant": "global", "privilege_rank": 2},
                ],
                "resources": [
                    {
                        "id": "order_tenant_a",
                        "url": f"{base_url}/api/orders/order-tenant-a",
                        "owner": "tenant_a_user",
                        "tenant": "tenant_a",
                        "methods": ["GET"],
                        "expected": {
                            "anonymous": {"status": [401, 403, 404]},
                            "tenant_a_user": {"status": [200], "required_fields": ["id", "tenant", "amount"]},
                            "tenant_a_support": {
                                "status": [200],
                                "required_fields": ["id", "tenant", "amount"],
                                "forbidden_fields": ["secret_note"],
                            },
                            "tenant_b_user": {"status": [403, 404], "forbidden_fields": ["tenant", "amount", "secret_note"]},
                            "administrator": {"status": [200], "required_fields": ["id", "tenant", "amount"]},
                        },
                    }
                ],
                "invariants": [
                    {
                        "id": "INV-BENCH-TENANT-001",
                        "type": "tenant_isolation",
                        "subject": "tenant_b_user",
                        "resource": "order_tenant_a",
                        "statement": "tenant_b_user must not read tenant_a order data",
                        "severity": "CRITICAL",
                    },
                    {
                        "id": "INV-BENCH-FIELD-001",
                        "type": "field_authorization",
                        "subject": "tenant_a_support",
                        "resource": "order_tenant_a",
                        "statement": "tenant_a_support must not observe secret_note",
                        "severity": "HIGH",
                    },
                ],
                "workflows": [],
            }
        )

    @staticmethod
    def _expected_violation_cases() -> List[str]:
        return [
            "tenant_b_user|order_tenant_a|GET",
            "tenant_a_support|order_tenant_a|GET",
        ]

    @staticmethod
    def _client(fixture):
        from ersec import ScanConfig, SafeHttpClient
        cfg = ScanConfig(target=fixture.base_url)
        host = fixture.base_url.split("://", 1)[1].split(":", 1)[0]
        port = int(fixture.base_url.rsplit(":", 1)[1])
        cfg.scope.allowed_hosts = [host]
        cfg.scope.allowed_ports = [port]
        cfg.scope.allow_private_addresses = True
        cfg.scope.allowed_methods = ["GET"]
        cfg.scope.max_requests = 100
        cfg.timeout_seconds = 2.0
        return SafeHttpClient(cfg)

    @classmethod
    def run_variant(cls, *, vulnerable: bool) -> BenchmarkRun:
        variant = "vulnerable" if vulnerable else "fixed"
        fixture = start_multitenant_authorization_fixture(vulnerable=vulnerable)
        try:
            model = cls._model(fixture.base_url)
            client = cls._client(fixture)
            verifier = AuthorizationAssuranceEngine()
            rows: List[Dict[str, Any]] = []
            started = time.perf_counter()
            request_count = 0
            for identity in model.identities:
                url = f"{fixture.base_url}/api/orders/order-tenant-a"
                request_count += 1
                try:
                    response = client.request(
                        "GET",
                        url,
                        headers={"X-ERSEC-Identity": identity.name},
                    )
                    try:
                        data = response.json()
                    except Exception:
                        data = None
                    paths = json_field_paths(data) if isinstance(data, (dict, list)) else []
                    rows.append(
                        {
                            "identity": identity.name,
                            "resource_id": "order_tenant_a",
                            "method": "GET",
                            "url": url,
                            "status": response.status_code,
                            "observed_fields": paths,
                            "verdict": "executed",
                        }
                    )
                except Exception as exc:
                    rows.append(
                        {
                            "identity": identity.name,
                            "resource_id": "order_tenant_a",
                            "method": "GET",
                            "url": url,
                            "verdict": "inconclusive",
                            "error": str(exc),
                        }
                    )
            duration = time.perf_counter() - started
            assurance = verifier.evaluate(model, {"verifications": rows})
            return BenchmarkRun(
                variant=variant,
                status=assurance["status"],
                report=assurance,
                runtime_seconds=round(duration, 6),
                request_count=request_count,
            )
        finally:
            fixture.close()

    @classmethod
    def run(cls) -> Dict[str, Any]:
        runs = [cls.run_variant(vulnerable=True), cls.run_variant(vulnerable=False)]
        vulnerable = runs[0]
        fixed = runs[1]
        expected = set(cls._expected_violation_cases())
        observed_vulnerable = {
            str(item.get("case_id")) for item in vulnerable.report.get("violations", []) if isinstance(item, Mapping)
        }
        observed_fixed = {
            str(item.get("case_id")) for item in fixed.report.get("violations", []) if isinstance(item, Mapping)
        }
        true_positives = len(expected & observed_vulnerable)
        false_positives = max(0, len(observed_vulnerable - expected))
        false_negatives = len(expected - observed_vulnerable)
        precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 1.0
        recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        fixed_safe = not observed_fixed
        status = "pass" if fixed_safe and false_positives == 0 and false_negatives == 0 else "fail"
        return {
            "schema": AUTHZ_BENCHMARK_SCHEMA,
            "benchmark_id": "multitenant-rest-v1",
            "status": status,
            "oracle": {
                "type": "operator-reviewed-ground-truth",
                "expected_vulnerable_cases": sorted(expected),
                "fixed_variant_must_have_zero_violations": True,
            },
            "variants": [
                {"name": r.variant, "status": r.status, "runtime_seconds": r.runtime_seconds, "request_count": r.request_count, "coverage_ratio": r.report.get("coverage_ratio"), "counts": r.report.get("counts")} for r in runs
            ],
            "quality": {
                "true_positives": true_positives,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "fixed_variant_safe": fixed_safe,
            },
            "reproducibility": {
                "deterministic_identities": True,
                "deterministic_objects": True,
                "loopback_only": True,
                "state_changes": False,
                "seed_material": "built-in-v1",
            },
            "statement": "This benchmark measures semantic authorization assurance on a deterministic local target. It is not a claim about arbitrary applications or competitor performance.",
        }

    @classmethod
    def write(cls, path: str) -> Dict[str, Any]:
        result = cls.run()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result
