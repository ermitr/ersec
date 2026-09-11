import json
from pathlib import Path
from ersec.ersec_workspace import AssessmentWorkspace, export_workspace, normalize_url, stable_id


def test_url_normalization_and_stable_identity():
    assert normalize_url("HTTPS://Example.test:443/a?b=2&a=1") == "https://example.test/a?a=1&b=2"
    assert stable_id("asset", "Example.test") == stable_id("asset", "Example.test")


def test_nmap_and_openapi_deduplicate_operations(tmp_path: Path):
    ws = AssessmentWorkspace.create(tmp_path / "case", target="https://example.test")
    nmap = tmp_path / "scan.xml"
    nmap.write_text('''<nmaprun><host><address addr="example.test"/><ports><port portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>''')
    ws.import_file(nmap)
    api = tmp_path / "api.json"
    api.write_text(json.dumps({"openapi":"3.0.0","servers":[{"url":"https://example.test"}],"paths":{"/api/orders":{"get":{"operationId":"orders"}}}}))
    ws.import_file(api)
    ws.save()
    assert len(ws.data["assets"]) == 1
    assert len(ws.data["services"]) == 1
    assert len(ws.data["operations"]) == 1


def test_sarif_and_har_preserve_provenance(tmp_path: Path):
    ws = AssessmentWorkspace.create(tmp_path / "case")
    har = tmp_path / "traffic.har"
    har.write_text(json.dumps({"log":{"entries":[{"request":{"method":"GET","url":"https://example.test/api/x"}}]}}))
    ws.import_file(har)
    sarif = tmp_path / "results.sarif"
    sarif.write_text(json.dumps({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"results":[{"ruleId":"R1","message":{"text":"test"}}]}]}))
    ws.import_file(sarif)
    assert len(ws.data["operations"]) == 1
    assert len(ws.data["findings"]) == 1
    assert all("digest" in e["source"] for e in ws.data["evidence"])


def test_export_digest_ignores_import_timestamp(tmp_path: Path):
    ws = AssessmentWorkspace.create(tmp_path / "case")
    src = tmp_path / "domains.txt"; src.write_text("example.test\n")
    ws.import_file(src)
    a = export_workspace(ws)["digest"]
    # Changing only provenance wall-clock metadata must not alter semantic identity.
    ws.data["evidence"][0]["source"]["imported_at"] = "2099-01-01T00:00:00Z"
    b = export_workspace(ws)["digest"]
    assert a == b
