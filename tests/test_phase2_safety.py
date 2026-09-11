import json
from pathlib import Path
import pytest

from ersec.ersec_input_safety import InputSafetyError, loads_json, load_yaml, redact
from ersec.ersec_reports import AtomicReportWriter
from ersec.ersec_workspace import AssessmentWorkspace, ingest_nmap


def test_json_depth_and_size_boundaries():
    nested = "[" * 65 + "0" + "]" * 65
    with pytest.raises(InputSafetyError):
        loads_json(nested)
    with pytest.raises(InputSafetyError):
        loads_json((b"[" + b"0," * (4 * 1024 * 1024) + b"0]"))


def test_yaml_is_safe_and_bounded():
    assert load_yaml("a: 1\n") == {"a": 1}
    huge = "x: " + ("a" * (8 * 1024 * 1024))
    with pytest.raises(InputSafetyError):
        load_yaml(huge)


def test_redaction_covers_nested_secrets_and_url_tokens():
    value = {
        "Authorization": "Bearer SUPERSECRETTOKEN12345",
        "headers": {"Cookie": "sid=SUPERSECRET", "X-Api-Key": "APISECRET"},
        "url": "https://example.test/?token=URLSECRET&x=1",
        "nested": [{"password": "PWSECRET"}],
    }
    safe = redact(value)
    text = json.dumps(safe)
    for secret in ("SUPERSECRETTOKEN12345", "SUPERSECRET", "APISECRET", "URLSECRET", "PWSECRET"):
        assert secret not in text
    assert "[REDACTED]" in text


def test_report_writer_redacts_json_and_text(tmp_path):
    writer = AtomicReportWriter()
    out = tmp_path / "report.json"
    writer.write_json({"findings": [{"url": "https://e/?token=SECRET123", "Authorization": "Bearer SECRET456"}]}, str(out), validate=False)
    text = out.read_text()
    assert "SECRET123" not in text and "SECRET456" not in text
    assert "[REDACTED]" in text
    txt = tmp_path / "report.md"
    writer.write_text("Authorization: Bearer SECRET789", str(txt))
    assert "SECRET789" not in txt.read_text()


def test_nmap_input_size_and_hardened_parser(tmp_path):
    p = tmp_path / "safe.xml"
    raw = b'<nmaprun><host><address addr="example.test"/></host></nmaprun>'
    p.write_bytes(raw)
    ws = AssessmentWorkspace.create(tmp_path / "ws")
    result = ingest_nmap(ws, p, raw)
    assert result["hosts"] == 1


def test_workspace_does_not_persist_postman_auth_secret(tmp_path):
    p = tmp_path / "postman.json"
    p.write_text(json.dumps({"info": {}, "item": [{"name": "x", "request": {"method": "GET", "url": "https://example.test/x", "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "SECRET"}]}}}]}))
    ws = AssessmentWorkspace.create(tmp_path / "ws")
    ws.import_file(p, "postman")
    assert "SECRET" not in json.dumps(ws.data)
