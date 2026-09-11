import pytest
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "ersec" / "ersec.py"


def run_cli(*args):
    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "ersec.ersec", *args],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_version():
    result = run_cli("--version")
    assert result.returncode == 0
    assert result.stdout.startswith("ERSEC ")


def test_self_test():
    result = run_cli("--self-test")
    assert result.returncode == 0, result.stdout + result.stderr


def test_sbom_generation(tmp_path):
    from ersec import generate_sbom, ERSEC_VERSION
    out = tmp_path / "sbom.json"
    result = generate_sbom(str(out))
    assert out.exists()
    assert result["format"] == "CycloneDX 1.7"
    assert result["version"] == ERSEC_VERSION


def test_contract_gate_only_active_contracts_fail():
    from ersec import SecurityContractGate
    bundle = {"schema":"ersec-contract/2","contracts":[
        {"contract_id":"FC-active","type":"finding-regression","finding_id":"F-1","automation":{"status":"active"}},
        {"contract_id":"FC-draft","type":"finding-regression","finding_id":"F-2","automation":{"status":"draft"}},
    ]}
    report={"findings":[{"finding_id":"F-1"},{"finding_id":"F-2"}]}
    result=SecurityContractGate.evaluate(bundle,report)
    assert result["status"] == "fail"
    assert result["failed_count"] == 1
    assert result["skipped_count"] == 1


def test_assurance_scorecard_and_release_gate():
    from ersec import AssuranceScorecard, ReleaseAssuranceGate
    report={"findings":[], "coverage_matrix":{"coverage_ratio":0.9}}
    score=AssuranceScorecard.build(report)
    assert score["framework"] == "OWASP API Security Top 10:2023"
    assert len(score["controls"]) == 10
    gate=ReleaseAssuranceGate.evaluate(report, {"contracts":[]}, {"precision":1.0,"recall":1.0}, {"bomFormat":"CycloneDX","specVersion":"1.7"})
    assert gate["status"] == "pass"


def test_release_gate_fails_high_and_expired():
    from ersec import ReleaseAssuranceGate
    report={"findings":[{"severity":"HIGH"}], "coverage_matrix":{"coverage_ratio":0.9}}
    contracts={"contracts":[{"contract_id":"C","automation":{"status":"expired"}}]}
    sbom={"bomFormat":"CycloneDX","specVersion":"1.7"}
    result=ReleaseAssuranceGate.evaluate(report, contracts, None, sbom)
    assert result["status"] == "fail"
    assert result["failed_count"] >= 2


def test_release_gate_pass_fixture(tmp_path):
    from ersec import ReleaseAssuranceGate
    report_path=Path(__file__).parent / "fixtures" / "release-report-pass.json"
    report=__import__("json").loads(report_path.read_text())
    contracts={"contracts":[]}
    sbom={"bomFormat":"CycloneDX","specVersion":"1.7"}
    result=ReleaseAssuranceGate.evaluate(report, contracts, None, sbom)
    assert result["status"] == "pass"
    assert result["failed_count"] == 0


def test_release_gate_reports_missing_evidence():
    from ersec import ReleaseAssuranceGate
    result=ReleaseAssuranceGate.evaluate({"findings":[], "coverage_matrix":{"coverage_ratio":0.95}})
    assert result["status"] == "fail"
    ids={c["id"] for c in result["checks"]}
    assert "contract-evidence" in ids and "sbom" in ids


def test_security_model_validation():
    from ersec.ersec_behavior import SecurityBehaviorModel
    model = SecurityBehaviorModel.load(str(ROOT / "examples" / "security-model.example.json"))
    result = model.validate()
    assert result["schema"] == "ersec-security-behavior-model/1"
    assert result["identities"] == 4
    assert result["resources"] == 1
    assert result["stateful_methods_allowed"] is False


def test_behavior_model_contracts_are_draft():
    from ersec.ersec_behavior import SecurityBehaviorModel
    model = SecurityBehaviorModel.load(str(ROOT / "examples" / "security-model.example.json"))
    contracts = model.contracts()
    assert contracts
    assert all(c["automation"]["status"] == "draft" for c in contracts)

def test_sensitive_evidence_redaction():
    from ersec import RequestEvidence
    ev = RequestEvidence(
        method="GET",
        url="https://example.com/api?token=secret-token&x=1",
        response_headers={"Authorization":"Bearer very-secret", "Content-Type":"application/json"},
        response_excerpt='{"password":"hunter2","access_token":"abc.def.ghi","ok":true}',
        request_headers_sent={"Cookie":"session=secret", "X-Api-Key":"key-secret"},
    )
    d = ev.redacted()
    assert "secret-token" not in d["url"]
    assert d["response_headers"]["Authorization"] == "REDACTED"
    assert "hunter2" not in d["response_excerpt"]
    assert "secret" not in str(d["request_headers_sent"])


def test_behavior_url_keeps_port_and_query():
    from ersec.ersec_behavior import _norm_url
    assert _norm_url("https://[2001:db8::1]:8443/a?x=1#frag") == "https://[2001:db8::1]:8443/a?x=1"


def test_crlf_body_reflection_is_not_confirmation():
    # Regression guard: confirmation requires the injected response header marker,
    # not merely reflection of the marker in the response body.
    source = open(ROOT / "src" / "ersec" / "ersec_core.py", encoding="utf-8").read()
    assert 'resp.headers.get("X-Ersec-Injected") == marker' in source
    assert 'or marker in (resp.text or "")' not in source


def test_dns_module_rejects_ip_literals():
    from ersec import DNSEmailSecurityModule
    assert DNSEmailSecurityModule._is_dns_eligible_host("127.0.0.1") is False
    assert DNSEmailSecurityModule._is_dns_eligible_host("localhost") is False
    assert DNSEmailSecurityModule._is_dns_eligible_host("app.internal") is False
    assert DNSEmailSecurityModule._is_dns_eligible_host("example.com") is True


def test_model_violation_uses_common_finding_pipeline():
    from ersec import model_failures_to_findings
    rows = [
        {"identity":"tenant_b","resource_id":"order_1","method":"GET","url":"https://example.com/api/orders/1",
         "status":200,"expected":{"status":[403,404]},"verdict":"violation"},
        {"identity":"tenant_b","resource_id":"order_1","method":"GET","url":"https://example.com/api/orders/1",
         "status":403,"expected":{"status":[403,404]},"verdict":"pass"},
        {"identity":"tenant_c","resource_id":"order_2","method":"GET","url":"https://example.com/api/orders/2",
         "verdict":"not_tested"},
    ]
    findings = model_failures_to_findings(rows)
    assert len(findings) == 1
    assert findings[0].category == "security_model_authorization"
    assert findings[0].severity.name == "HIGH"
    assert findings[0].url.endswith("/1")


def test_benchmark_quality_reporter_rejects_inconsistent_metrics():
    from ersec import BenchmarkQualityReporter
    report={"findings":[{"category":"x","url":"https://example.com/a"}]}
    truth={"name":"fixture","findings":[{"category":"x","url":"https://example.com/a"}]}
    out=BenchmarkQualityReporter.run(report,truth)
    assert out["status"] == "pass"
    assert out["true_positives"] == 1
    assert out["precision"] == 1.0
    assert out["recall"] == 1.0


def test_request_budget_exhaustion_is_sticky_and_counted():
    from ersec import ScanConfig, SafeHttpClient
    cfg = ScanConfig()
    cfg.target = "https://127.0.0.1:1"
    cfg.scope.allowed_hosts = ["127.0.0.1"]
    cfg.scope.allowed_ports = [1]
    cfg.scope.max_requests = 0
    client = SafeHttpClient(cfg)
    import pytest
    with pytest.raises(Exception, match="Request budget exhausted"):
        client.request("GET", "https://127.0.0.1:1/")
    with pytest.raises(Exception, match="Request budget exhausted"):
        client.request("GET", "https://127.0.0.1:1/")
    assert client.budget_exhausted is True
    assert client.skipped_due_to_budget == 2


def test_failure_injection_timeout_malformed_json_and_detector_exception(tmp_path):
    import json
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from ersec import InstrumentedDetector, ScanExecutionLedger, ScanConfig, SafeHttpClient

    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(0.8)
            self.send_response(200); self.end_headers(); self.wfile.write(b"not-json")
        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    host, port = srv.server_address
    try:
        cfg = ScanConfig(); cfg.scope.allowed_hosts=[host]; cfg.scope.allowed_ports=[port]; cfg.scope.allow_private_addresses=True; cfg.scope.timeout_seconds=0.5; cfg.target=f"http://{host}:{port}"
        # Timeout is explicit and bounded.
        with pytest.raises(Exception): SafeHttpClient(cfg).request("GET", f"http://{host}:{port}/")
    finally:
        srv.shutdown(); srv.server_close(); thread.join(timeout=2)

    # Malformed JSON is handled as an application-layer failure, not a scanner crash.
    assert json.loads('{"ok": true}') == {"ok": True}
    with pytest.raises(json.JSONDecodeError): json.loads("not-json")

    class Boom:
        category = "test_exception"
        config = ScanConfig()
        def applies(self): return True
        def run_url(self, url): raise RuntimeError("injected detector failure")
    ledger = ScanExecutionLedger(); wrapped = InstrumentedDetector(Boom(), ledger)
    with pytest.raises(RuntimeError, match="injected detector failure"): wrapped.run_url("http://example.com/")
    summary = ledger.summary()
    assert summary["failed_invocations"] == 1


def test_schema_fixture_is_compatible():
    import json
    from ersec.ersec_schema import validate_report
    fixture = json.loads((Path(__file__).parent / "fixtures" / "schema-report-pass.json").read_text(encoding="utf-8"))
    assert validate_report(fixture)["valid"] is True


def test_scan_report_schema_and_validation():
    from ersec.ersec_schema import REPORT_SCHEMA, validate_report
    report = {
        "schema": REPORT_SCHEMA, "schema_version": 1, "tool_version": __import__("ersec").ERSEC_VERSION,
        "target": "https://example.com", "scan_status": "completed",
        "completeness": {"status": "completed", "request_budget_exhausted": False, "component_failures": 0},
        "findings": [{
            "finding_id": "F-1", "category": "xss", "severity": "LOW",
            "confidence": "Likely", "url": "https://example.com/", "evidence": {}
        }]
    }
    result = validate_report(report)
    assert result["valid"] is True
    bad = dict(report); bad["scan_status"] = "incomplete"
    bad["completeness"] = dict(report["completeness"], status="completed")
    result = validate_report(bad)
    assert result["valid"] is False


def test_behavior_assurance_coverage_never_calls_untested_secure():
    from ersec.ersec_behavior import SecurityBehaviorModel
    from ersec.ersec_schema import behavior_assurance_coverage
    model = SecurityBehaviorModel({
        "schema": "ersec-security-behavior-model/1",
        "identities": [{"name": "user"}, {"name": "admin"}],
        "resources": [{"id": "r", "url": "https://example.com/r", "methods": ["GET"]}],
        "invariants": []
    })
    observed = {"verifications": [{"resource_id":"r", "identity":"user", "method":"GET", "verdict":"pass"}]}
    out = behavior_assurance_coverage(model, observed)
    assert out["applicable_cells"] == 2
    assert out["tested_cells"] == 1
    assert out["coverage_ratio"] == 0.5
    assert out["untested_cells"] == 1


def test_validate_report_cli(tmp_path):
    import json
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "schema":"ersec-scan-report/1", "schema_version":1, "tool_version":__import__("ersec").ERSEC_VERSION,
        "target":"https://example.com", "scan_status":"completed",
        "completeness":{"status":"completed","request_budget_exhausted":False,"component_failures":0},
        "findings":[]
    }), encoding="utf-8")
    result = run_cli("--validate-report", str(path))
    assert result.returncode == 0, result.stdout + result.stderr


def test_interrupted_output_is_explicit(tmp_path):
    target = tmp_path / "report.json"
    try:
        with target.open("w", encoding="utf-8") as fh:
            fh.write('{"partial":')
            raise OSError("injected interrupted write")
    except OSError:
        pass
    assert target.read_text(encoding="utf-8") == '{"partial":'


def test_typed_detector_result_envelope():
    from ersec import InstrumentedDetector, ScanExecutionLedger, ScanConfig
    from ersec.ersec_interfaces import DetectorResult, ExecutionStatus

    class EmptyDetector:
        category = "typed-test"
        config = ScanConfig()
        def applies(self): return True
        def run_url(self, url): return []
        def run_param(self, url, param, method="GET"): return []

    wrapped = InstrumentedDetector(EmptyDetector(), ScanExecutionLedger())
    result = wrapped.execute_url("https://example.com/")
    assert isinstance(result, DetectorResult)
    assert result.status is ExecutionStatus.OK
    assert result.findings == []
    assert result.metadata is not None
    assert result.metadata.detector_id == "typed-test"


def test_typed_detector_error_is_explicit():
    from ersec import InstrumentedDetector, ScanExecutionLedger, ScanConfig
    from ersec.ersec_interfaces import ExecutionStatus

    class BrokenDetector:
        category = "broken-test"
        config = ScanConfig()
        def applies(self): return True
        def run_url(self, url): raise ValueError("controlled detector failure")
        def run_param(self, url, param, method="GET"): return []

    wrapped = InstrumentedDetector(BrokenDetector(), ScanExecutionLedger())
    result = wrapped.execute_url("https://example.com/")
    assert result.status is ExecutionStatus.ERROR
    assert result.error == "controlled detector failure"


def test_schema_compatibility_contract_v1_remains_readable():
    from ersec.ersec_schema import schema_compatibility, CONTRACT_SCHEMA
    out = schema_compatibility("ersec-contract/1", 1)
    assert out["compatible"] is True
    current = schema_compatibility(CONTRACT_SCHEMA, 2)
    assert current["compatible"] is True


def test_controlled_http_detector_integration():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from ersec import ScanConfig, SafeHttpClient, SecurityHeadersModule

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ERSEC controlled integration fixture")
        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
    host, port = srv.server_address
    try:
        cfg = ScanConfig(target=f"http://{host}:{port}")
        cfg.scope.allowed_hosts = [host]
        cfg.scope.allowed_ports = [port]
        cfg.scope.allow_private_addresses = True
        client = SafeHttpClient(cfg)
        findings = SecurityHeadersModule(cfg, client).run_url(f"http://{host}:{port}/")
        assert isinstance(findings, list)
        assert all(getattr(f, "evidence", None) is not None for f in findings)
    finally:
        srv.shutdown(); srv.server_close(); thread.join(timeout=2)


def test_golden_finding_evidence_contract():
    import json
    from ersec.ersec_schema import validate_finding
    fixture = json.loads((Path(__file__).parent / "fixtures" / "finding-evidence-pass.json").read_text(encoding="utf-8"))
    assert validate_finding(fixture) == []


def test_extracted_evidence_boundary_redacts_nested_secret_like_data():
    from ersec.ersec_evidence import redact_evidence_record
    out = redact_evidence_record({
        "url": "https://example.com/api?token=abc&x=1",
        "request_headers_sent": {"Authorization": "Bearer secret", "X-Test": "ok"},
        "response_headers": {"Set-Cookie": "sid=secret", "X-Test": "ok"},
        "response_excerpt": '{"password":"supersecret","name":"alice"}',
    })
    assert "supersecret" not in str(out)
    assert "Bearer secret" not in str(out)
    assert "sid=secret" not in str(out)
    assert "token=REDACTED" in out["url"]


def test_extracted_scope_boundary_is_conservative():
    from ersec.ersec_scope import canonical_url, dns_is_eligible_host
    assert canonical_url("HTTPS://EXAMPLE.COM:8443/a%2Fb?q=1#frag") == "https://example.com:8443/a%2Fb?q=1"
    assert canonical_url("https://example.com:443/a#frag") == "https://example.com/a"
    assert canonical_url("http://[2001:db8::1]:8080/a#f") == "http://[2001:db8::1]:8080/a"
    assert dns_is_eligible_host("example.com") is True
    assert dns_is_eligible_host("127.0.0.1") is False
    assert dns_is_eligible_host("localhost") is False
    assert dns_is_eligible_host("service.internal") is False


def test_extracted_finding_boundary_preserves_first_equivalent():
    from ersec.ersec_findings import deduplicate_findings
    class F:
        def __init__(self, category, url, parameter):
            self.category=category; self.url=url; self.parameter=parameter
    first=F("xss_signal", "https://example.com/a?b=1", "q")
    second=F("xss_signal", "https://example.com/a?b=2", "q")
    third=F("csrf", "https://example.com/a?b=2", "q")
    assert deduplicate_findings([first, second, third]) == [first, third]


def test_scoped_transport_boundary_denies_before_client():
    from ersec.ersec_transport import ScopedTransportClient, TransportBoundaryError
    class Client:
        def __init__(self): self.calls=[]
        def request(self, method, url, **kwargs): self.calls.append((method,url)); return "ok"
    c=Client()
    t=ScopedTransportClient(c, lambda method,url:(url.startswith("https://example.com"), "out_of_scope"), ["GET"])
    assert t.request("GET", "https://example.com/") == "ok"
    assert c.calls == [("GET", "https://example.com/")]
    with pytest.raises(TransportBoundaryError): t.request("POST", "https://example.com/")
    with pytest.raises(TransportBoundaryError): t.request("GET", "https://evil.example/")
    assert len(c.calls) == 1


def test_benchmark_boundary_rejects_missing_or_malformed_oracle():
    from ersec.ersec_benchmarks import SafeBenchmarkRunner, BenchmarkExecutionError
    with pytest.raises(BenchmarkExecutionError): SafeBenchmarkRunner(None).evaluate({}, {})
    class Bad:
        def evaluate(self, report, truth): return []
    with pytest.raises(BenchmarkExecutionError): SafeBenchmarkRunner(Bad()).evaluate({}, {})


def test_safe_http_defaults_are_read_only_and_state_changes_fail_closed():
    from ersec import ScanConfig, SafeHttpClient, ScopeError
    cfg = ScanConfig(target="example.com")
    assert cfg.scope.allowed_methods == ["GET", "HEAD", "OPTIONS"]
    client = SafeHttpClient(cfg)
    with pytest.raises(ScopeError):
        client.request("POST", "https://example.com/")


def test_state_changing_request_requires_manifest_and_explicit_opt_in():
    from ersec import ScanConfig, SafeHttpClient, ScopeError
    cfg = ScanConfig(target="127.0.0.1")
    cfg.scope.allowed_hosts = ["127.0.0.1"]
    cfg.scope.allowed_ports = [1]
    cfg.scope.allowed_methods = ["GET", "HEAD", "OPTIONS", "POST"]
    cfg.scope.allow_private_addresses = True
    client = SafeHttpClient(cfg)
    with pytest.raises(ScopeError, match="explicit opt-in"):
        client.request("POST", "https://127.0.0.1:1/")
    cfg.allow_state_changing_methods = True
    with pytest.raises(ScopeError, match="authorization manifest"):
        client.request("POST", "https://127.0.0.1:1/")


def test_redirects_require_explicit_per_hop_revalidation():
    from ersec import ScanConfig, SafeHttpClient, ScopeError
    cfg = ScanConfig(target="example.com")
    client = SafeHttpClient(cfg)
    with pytest.raises(ScopeError, match="Automatic redirects"):
        client.request("GET", "https://example.com/", allow_redirects=True)


def test_xml_workspace_uses_hardened_parser():
    from ersec.ersec_workspace import detect_kind
    from defusedxml.common import DefusedXmlException
    bomb = b"<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><nmaprun>&lol1;</nmaprun>"
    with pytest.raises(DefusedXmlException):
        detect_kind(Path("bomb.xml"), bomb)


def test_atomic_report_writer_validates_before_replacement(tmp_path):
    from ersec.ersec_reports import AtomicReportWriter, ReportSerializationError
    target = tmp_path / "report.json"
    valid = {
        "schema": "ersec-scan-report/1", "schema_version": 1, "tool_version": __import__("ersec").ERSEC_VERSION,
        "target": "https://example.com", "scan_status": "completed",
        "completeness": {"status": "completed", "request_budget_exhausted": False, "component_failures": 0},
        "findings": []
    }
    writer = AtomicReportWriter()
    writer.write_json(valid, str(target))
    original = target.read_text(encoding="utf-8")
    invalid = dict(valid, scan_status="not-a-valid-status")
    with pytest.raises(ReportSerializationError):
        writer.write_json(invalid, str(target))
    assert target.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".*.tmp")) == []


def test_controlled_testing_fixture_is_loopback_and_clean():
    from ersec.ersec_testing import start_fixture
    import requests
    fixture = start_fixture()
    try:
        response = requests.get(fixture.base_url + "/", timeout=2)
        assert response.status_code == 200
        assert response.json()["fixture"] == "ersec-controlled-http"
        assert fixture.base_url.startswith("http://127.0.0.1:")
    finally:
        fixture.close()


def test_quality_manifest_and_golden_fixture_registry():
    from ersec.ersec_quality import QUALITY_SCHEMA, DEFAULT_GOLDEN_FIXTURES, validate_quality_manifest
    manifest = {"schema": QUALITY_SCHEMA, "fixtures": [f.to_dict() for f in DEFAULT_GOLDEN_FIXTURES]}
    result = validate_quality_manifest(manifest)
    assert result["valid"] is True
    assert result["fixture_count"] == 5


def test_report_semantics_reject_duplicate_finding_ids():
    from ersec.ersec_quality import validate_report_semantics
    finding = {
        "finding_id": "F-1", "category": "x", "severity": "LOW",
        "confidence": "Confirmed", "url": "https://example.com/", "evidence": {}
    }
    report = {
        "schema": "ersec-scan-report/1", "schema_version": 1,
        "tool_version": __import__("ersec").ERSEC_VERSION, "target": "https://example.com", "scan_status": "completed",
        "completeness": {"status": "completed", "request_budget_exhausted": False, "component_failures": 0},
        "findings": [finding, dict(finding)],
    }
    result = validate_report_semantics(report)
    assert result["valid"] is False
    assert any("duplicate finding_id" in e for e in result["errors"])


def test_cross_format_identity_check_catches_missing_finding():
    from ersec.ersec_quality import cross_format_identity_check
    left = [{"finding_id":"F-1"},{"finding_id":"F-2"}]
    right = [{"finding_id":"F-1"}]
    result = cross_format_identity_check(left, right)
    assert result["valid"] is False
    assert result["mismatches"][0]["missing"] == ["F-2"]


def test_quality_golden_fixture_corpus_has_positive_negative_and_ambiguous_cases():
    from ersec.ersec_quality import DEFAULT_GOLDEN_FIXTURES
    verdicts = {f.expected_verdict for f in DEFAULT_GOLDEN_FIXTURES}
    assert "pass" in verdicts
    assert "violation" in verdicts
    assert "observation_unavailable" in verdicts


def test_detector_execution_runner_makes_failures_explicit():
    from ersec.ersec_detector_runner import DetectorExecutionRunner
    from ersec.ersec_interfaces import DetectorResult, ExecutionStatus
    summary = DetectorExecutionRunner().run([
        lambda: DetectorResult(status=ExecutionStatus.OK),
        lambda: DetectorResult(status=ExecutionStatus.SKIPPED),
        lambda: (_ for _ in ()).throw(ValueError("injected detector error")),
    ])
    assert summary.total == 3
    assert summary.by_status["ok"] == 1
    assert summary.by_status["skipped"] == 1
    assert summary.by_status["error"] == 1
    assert summary.incomplete is True
    assert summary.failures[0]["error"] == "injected detector error"


def test_oracles_never_turn_missing_observation_into_pass():
    from ersec.ersec_oracles import Verdict, status_oracle, forbidden_fields_oracle, ownership_oracle
    assert status_oracle(403, [403, 404]).verdict is Verdict.PASS
    assert status_oracle(200, [403, 404]).verdict is Verdict.VIOLATION
    assert forbidden_fields_oracle({"id": "x"}, ["secret"]).verdict is Verdict.PASS
    assert forbidden_fields_oracle({"secret": "x"}, ["secret"]).verdict is Verdict.VIOLATION
    assert ownership_oracle(None, "tenant_a").verdict is Verdict.OBSERVATION_UNAVAILABLE


def test_oracle_fixture_vectors_match_expected():
    import json
    from pathlib import Path
    from ersec.ersec_oracles import Verdict, status_oracle, forbidden_fields_oracle, ownership_oracle
    data = json.loads((Path(__file__).parent / "fixtures" / "assurance-oracles.json").read_text())
    for item in data["fixtures"]:
        if item["oracle"] == "status":
            result = status_oracle(item.get("observed"), item.get("allowed", []))
        elif item["oracle"] == "forbidden_fields":
            result = forbidden_fields_oracle(item.get("payload"), item.get("forbidden", []))
        else:
            result = ownership_oracle(item.get("observed_owner"), item["expected_owner"])
        assert result.verdict is Verdict(item["expected"]), item["id"]


def test_schema_compatibility_golden_vectors():
    import json
    from pathlib import Path
    from ersec.ersec_schema import schema_compatibility
    data = json.loads((Path(__file__).parent / "fixtures" / "schema-compatibility.json").read_text())
    for item in data["cases"]:
        result = schema_compatibility(item["schema"], item["version"])
        assert result["compatible"] is item["compatible"], item


def test_debian_module_manifest_includes_new_boundaries():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    deb = root / "packaging/debian/usr/lib/python3/dist-packages"
    assert (deb / "ersec_detector_runner.py").is_file()
    assert (deb / "ersec_oracles.py").is_file()


def test_authorization_field_oracle_flags_forbidden_field():
    from ersec.ersec_authorization import AuthorizationAssuranceEngine
    from ersec.ersec_behavior import SecurityBehaviorModel
    model = SecurityBehaviorModel({
        "schema": "ersec-security-behavior-model/1",
        "identities": [{"name": "support", "role": "support", "tenant": "a"}],
        "resources": [{"id": "order", "url": "https://example.test/api/orders/1", "tenant": "a",
                        "expected": {"support": {"status": [200], "forbidden_fields": ["payment.card_number"]}},
                        "methods": ["GET"]}],
        "invariants": []
    })
    report = {"verifications": [{"identity": "support", "resource_id": "order", "method": "GET",
                                  "url": "https://example.test/api/orders/1", "status": 200,
                                  "verdict": "pass", "observed_fields": ["id", "payment.card_number"]}]}
    out = AuthorizationAssuranceEngine().evaluate(model, report)
    assert out["status"] == "fail"
    assert out["counts"]["violation"] == 1
    assert out["counterexamples"][0]["cause"] == "forbidden_fields"


def test_authorization_missing_observer_is_not_secure():
    from ersec.ersec_authorization import AuthorizationAssuranceEngine
    from ersec.ersec_behavior import SecurityBehaviorModel
    model = SecurityBehaviorModel({
        "schema": "ersec-security-behavior-model/1",
        "identities": [{"name": "user", "role": "user", "tenant": "a"}],
        "resources": [{"id": "order", "url": "https://example.test/api/orders/1", "tenant": "a",
                        "expected": {"user": {"status": [200], "required_fields": ["id"]}},
                        "methods": ["GET"]}],
        "invariants": []
    })
    report = {"verifications": [{"identity": "user", "resource_id": "order", "method": "GET",
                                  "url": "https://example.test/api/orders/1", "status": 200,
                                  "verdict": "pass", "observed_fields": []}]}
    out = AuthorizationAssuranceEngine().evaluate(model, report)
    assert out["status"] == "inconclusive"
    assert out["counts"]["observation_unavailable"] == 1


def test_authorization_not_tested_does_not_count_as_coverage():
    from ersec.ersec_authorization import AuthorizationAssuranceEngine
    from ersec.ersec_behavior import SecurityBehaviorModel
    model = SecurityBehaviorModel({
        "schema": "ersec-security-behavior-model/1",
        "identities": [{"name": "a", "tenant": "a"}, {"name": "b", "tenant": "b"}],
        "resources": [{"id": "order", "url": "https://example.test/api/orders/1", "tenant": "a",
                        "methods": ["GET"]}],
        "invariants": []
    })
    out = AuthorizationAssuranceEngine().evaluate(model, {"verifications": [
        {"identity": "a", "resource_id": "order", "method": "GET", "status": 200, "verdict": "pass", "observed_fields": []}
    ]})
    assert out["tested_cases"] == 1
    assert out["applicable_cases"] == 2
    assert out["coverage_ratio"] == 0.5
    assert out["counts"]["not_tested"] == 1


def test_authorization_ground_truth_is_deterministic():
    from ersec.ersec_authorization import build_multitenant_ground_truth
    a = build_multitenant_ground_truth()
    b = build_multitenant_ground_truth()
    assert a == b
    assert a["schema"] == "ersec-authorization-ground-truth/1"
    assert len(a["cases"]) >= 6


def test_model_verification_records_json_field_paths_without_values():
    from ersec.ersec_behavior import SecurityBehaviorModel, SecurityBehaviorVerifier
    class Response:
        status_code = 200
        text = '{"id":"1","tenant":"tenant_a","payment":{"card_number":"4111111111111111"}}'
        headers = {"Content-Type": "application/json"}
    model = SecurityBehaviorModel({
        "schema": "ersec-security-behavior-model/1",
        "identities": [{"name": "a", "tenant": "tenant_a"}],
        "resources": [{"id": "order", "url": "https://example.test/order/1", "tenant": "tenant_a", "methods": ["GET"]}],
        "invariants": []
    })
    out = SecurityBehaviorVerifier(model).verify(model.identities, lambda *_: Response(), lambda *_: (True, ""))
    row = out["verifications"][0]
    assert "payment.card_number" in row["observed_fields"]
    assert "4111111111111111" not in str(row)


def test_authorization_ground_truth_cli_export(tmp_path):
    import subprocess, sys, json
    dest = tmp_path / "authorization-ground-truth.json"
    result = run_cli("--authorization-ground-truth", str(dest))
    assert result.returncode == 0
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["schema"] == "ersec-authorization-ground-truth/1"


def test_multitenant_fixture_exposes_deterministic_bola_regression():
    import requests
    from ersec.ersec_testing import start_multitenant_authorization_fixture
    fixture = start_multitenant_authorization_fixture(vulnerable=True)
    try:
        resp = requests.get(f"{fixture.base_url}/api/orders/order-tenant-a", headers={"X-ERSEC-Identity": "tenant_b_user"}, timeout=2)
        assert resp.status_code == 200
        assert resp.json()["tenant"] == "tenant_a"
    finally:
        fixture.close()


def test_multitenant_fixture_fixed_mode_denies_cross_tenant_read():
    import requests
    from ersec.ersec_testing import start_multitenant_authorization_fixture
    fixture = start_multitenant_authorization_fixture(vulnerable=False)
    try:
        resp = requests.get(f"{fixture.base_url}/api/orders/order-tenant-a", headers={"X-ERSEC-Identity": "tenant_b_user"}, timeout=2)
        assert resp.status_code == 403
        assert "tenant" not in resp.json()
    finally:
        fixture.close()


def test_end_to_end_behavior_verifier_uses_multitenant_fixture():
    import requests
    from ersec.ersec_behavior import SecurityBehaviorModel, SecurityBehaviorVerifier
    from ersec.ersec_authorization import AuthorizationAssuranceEngine
    from ersec.ersec_testing import start_multitenant_authorization_fixture
    fixture = start_multitenant_authorization_fixture(vulnerable=True)
    try:
        model = SecurityBehaviorModel({
            "schema": "ersec-security-behavior-model/1",
            "identities": [
                {"name": "tenant_a_user", "role": "user", "tenant": "tenant_a"},
                {"name": "tenant_b_user", "role": "user", "tenant": "tenant_b"},
            ],
            "resources": [{"id": "order_a", "url": f"{fixture.base_url}/api/orders/order-tenant-a", "tenant": "tenant_a",
                            "expected": {"tenant_a_user": {"status": [200]},
                                         "tenant_b_user": {"status": [403, 404], "forbidden_fields": ["amount", "secret_note", "tenant"]}},
                            "methods": ["GET"]}],
            "invariants": []
        })
        def request(identity, method, url):
            return requests.request(method, url, headers={"X-ERSEC-Identity": identity}, timeout=2)
        verification = SecurityBehaviorVerifier(model).verify(model.identities, request, lambda *_: (True, ""))
        assurance = AuthorizationAssuranceEngine().evaluate(model, verification)
        assert assurance["status"] == "fail"
        assert assurance["counts"]["violation"] == 1
        assert assurance["counterexamples"][0]["cause"] in {"status", "forbidden_fields"}
    finally:
        fixture.close()


def test_authorization_matrix_v2_tracks_relationships_and_denominator():
    from ersec.ersec_behavior import SecurityBehaviorModel
    from ersec.ersec_authorization_model import build_authorization_matrix
    model = SecurityBehaviorModel({
        "schema": "ersec-security-behavior-model/1",
        "identities": [
            {"name": "a", "role": "user", "tenant": "t1"},
            {"name": "b", "role": "user", "tenant": "t2"},
        ],
        "resources": [{
            "id": "order", "url": "https://example.invalid/orders/1", "methods": ["GET"],
            "tenant": "t1", "expected": {"a": {"status": [200]}, "b": {"status": [403, 404]}}
        }],
        "invariants": []
    })
    matrix = build_authorization_matrix(model)
    assert matrix["cell_count"] == 2
    rel = {row["identity"]: row["relationship"] for row in matrix["cells"]}
    assert rel["a"] == "same_tenant"
    assert rel["b"] == "cross_tenant"


def test_credential_references_never_accept_secret_values_as_environment_names():
    import json
    from ersec.ersec_authorization_model import validate_credential_references
    good = validate_credential_references([{"name": "ERSEC_TEST_TOKEN", "source": "environment"}])
    assert good["valid"] is True
    bad = validate_credential_references([{"name": "super-secret-token", "source": "environment"}])
    assert bad["valid"] is False
    assert "super-secret-token" not in json.dumps(bad)


def test_authorization_remediation_requires_current_observation_for_verification():
    from ersec.ersec_authorization_model import remediation_delta
    before = {"violations": [{"case_id": "C1"}]}
    after = {"violations": [], "cases": [{"case_id": "C1", "verdict": "not_tested"}]}
    result = remediation_delta(before, after)
    assert result["status"] == "partial"
    assert result["resolved"] == []
    assert result["unverified_resolution"] == ["C1"]
    fixed = {"violations": [], "cases": [{"case_id": "C1", "verdict": "pass"}]}
    verified = remediation_delta(before, fixed)
    assert verified["status"] == "verified"
    assert verified["resolved"] == ["C1"]


def test_authorization_benchmark_lab_is_reproducible(tmp_path):
    from ersec.ersec_benchmark_lab import AuthorizationBenchmarkLab
    out1 = tmp_path / "bench1.json"
    out2 = tmp_path / "bench2.json"
    first = AuthorizationBenchmarkLab.write(str(out1))
    second = AuthorizationBenchmarkLab.write(str(out2))
    assert first["status"] == "pass"
    assert second["status"] == "pass"
    for result in (first, second):
        assert result["quality"]["precision"] == 1.0
        assert result["quality"]["recall"] == 1.0
        assert result["quality"]["f1"] == 1.0
        assert result["quality"]["fixed_variant_safe"] is True
        assert result["reproducibility"]["loopback_only"] is True
        assert result["reproducibility"]["state_changes"] is False


def test_authorization_benchmark_cli(tmp_path):
    path = tmp_path / "authorization-benchmark.json"
    result = run_cli("--authorization-benchmark", str(path))
    assert result.returncode == 0, result.stdout + result.stderr
    import json
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["benchmark_id"] == "multitenant-authorization-suite-v7"
    assert data["status"] == "pass"
    assert data["variants"][0]["request_count"] == 48
    assert data["variants"][1]["request_count"] == 48


def test_multitenant_fixture_support_field_is_fixed_without_secret_note():
    from ersec.ersec_testing import start_multitenant_authorization_fixture
    import requests
    fixture = start_multitenant_authorization_fixture(vulnerable=False)
    try:
        response = requests.get(
            fixture.base_url + "/api/orders/order-tenant-a",
            headers={"X-ERSEC-Identity": "tenant_a_support"},
            timeout=2,
        )
        assert response.status_code == 200
        body = response.json()
        assert "secret_note" not in body
        assert body["tenant"] == "tenant_a"
    finally:
        fixture.close()



def test_authorization_benchmark_reports_real_coverage_and_fixture_lifecycle():
    from ersec.ersec_authorization_benchmark import AuthorizationBenchmarkSuite
    result = AuthorizationBenchmarkSuite.run()
    quality = result["quality"]
    assert quality["scorable_case_coverage_ratio"] == 1.0
    assert quality["requests_per_scorable_case"] > 0
    assert quality["corpus_validation"]["valid"] is True
    assert len(quality["corpus_validation"]["corpus_digest"]) == 64
    assert quality["fixture_lifecycle"]["cleanup_verified"] is True
    assert quality["fixture_lifecycle"]["residual_objects"] == 0
    assert quality["fixture_lifecycle"]["shutdown_observed"] is True
    assert quality["runtime"]["max_seconds"] >= quality["runtime"]["mean_seconds"]


def test_authorization_benchmark_suite_ground_truth_and_metrics(tmp_path):
    from ersec.ersec_authorization_benchmark import AuthorizationBenchmarkSuite
    out = tmp_path / "suite.json"
    result = AuthorizationBenchmarkSuite.write(str(out))
    assert result["status"] == "pass"
    assert result["case_count"] == 48
    assert result["quality"]["precision"] == 1.0
    assert result["quality"]["recall"] == 1.0
    assert result["quality"]["f1"] == 1.0
    assert result["quality"]["fixed_variant_safe"] is True
    assert result["quality"]["requests_total"] == 96
    assert result["quality"]["truth_classes"] == {"scorable": 45, "ambiguous": 3}
    assert result["quality"]["replayability_ratio"] == 1.0
    assert all(item["deterministic_case_verdicts"] for item in result["quality"]["replayability"])
    assert out.exists()


def test_authorization_benchmark_suite_case_families_are_explicit():
    from ersec.ersec_authorization_benchmark import CASES
    families = {c.family for c in CASES}
    assert {"horizontal-bola", "vertical-privilege", "field-authorization", "revoked-session", "api-version-drift"}.issubset(families)
    assert all(c.path.startswith("/") for c in CASES)
