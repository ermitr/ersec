import json
import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ersec import AuthorizationManifest, ScanConfig, ScopeConfig, SafeHttpClient, ScopeError
from ersec_core import _scope_preview


def test_default_scope_is_read_only():
    scope = ScopeConfig()
    assert scope.allowed_methods == ["GET", "HEAD", "OPTIONS"]
    assert scope.allow_private_addresses is False
    assert scope.max_redirects == 5


def test_state_changing_requires_explicit_opt_in_and_manifest():
    cfg = ScanConfig(target="https://example.com")
    cfg.scope.allowed_hosts = ["example.com"]
    cfg.scope.allowed_ports = [443]
    cfg.scope.allowed_methods = ["GET", "POST"]
    client = SafeHttpClient(cfg)
    with pytest.raises(ScopeError, match="explicit opt-in"):
        client.dry_run("POST", "https://example.com/api", reason="authorized test")
    cfg.allow_state_changing_methods = True
    with pytest.raises(ScopeError, match="authorization manifest"):
        client.dry_run("POST", "https://example.com/api", reason="authorized test")


def test_manifest_cannot_expand_scope():
    manifest = AuthorizationManifest({
        "allowed_hosts": ["example.com"], "allowed_ports": [443],
        "allowed_paths": ["/api"], "allowed_methods": ["GET", "POST"],
        "private_address_policy": "allow",
    })
    assert manifest.allows_request("POST", "https://example.com/api/x")[0] is True
    assert manifest.allows_request("POST", "https://evil.example/api/x")[0] is False
    assert manifest.allows_request("GET", "https://example.com/public")[0] is False


def test_private_and_reserved_addresses_are_blocked(monkeypatch):
    cfg = ScanConfig(target="https://example.com")
    cfg.scope.allowed_hosts = ["example.com"]
    cfg.scope.allowed_ports = [443]
    client = SafeHttpClient(cfg)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
    ])
    with pytest.raises(ScopeError, match="private/reserved"):
        client._validate_network_address("https://example.com/")


def test_ipv4_mapped_ipv6_is_treated_as_ipv4_private(monkeypatch):
    cfg = ScanConfig(target="https://example.com")
    cfg.scope.allowed_hosts = ["example.com"]
    cfg.scope.allowed_ports = [443]
    client = SafeHttpClient(cfg)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 443, 0, 0)),
    ])
    with pytest.raises(ScopeError):
        client._validate_network_address("https://example.com/")


def test_redirects_are_reauthorized_per_hop():
    cfg = ScanConfig(target="https://example.com")
    cfg.scope.allowed_hosts = ["example.com"]
    cfg.scope.allowed_ports = [443]
    cfg.scope.allowed_methods = ["GET"]
    client = SafeHttpClient(cfg)
    class Resp:
        status_code = 302
        headers = {"Location": "https://evil.example/"}
    with patch.object(client, "request", side_effect=[Resp()]) as req:
        with pytest.raises(ScopeError):
            client.request_follow_redirects("GET", "https://example.com/")
        assert req.call_count == 1


def test_dry_run_never_resolves_or_contacts_network(monkeypatch):
    cfg = ScanConfig(target="https://example.com")
    cfg.scope.allowed_hosts = ["example.com"]
    cfg.scope.allowed_ports = [443]
    client = SafeHttpClient(cfg)
    called = False
    def fail(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network resolution occurred")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    result = client.dry_run("GET", "https://example.com/api", reason="preview")
    assert result["network_contact"] is False
    assert called is False


def test_scope_preview_is_offline(tmp_path, monkeypatch):
    manifest_path = tmp_path / "auth.json"
    manifest_path.write_text(json.dumps({
        "allowed_hosts": ["example.com"], "allowed_ports": [443],
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "private_address_policy": "deny",
    }))
    args = SimpleNamespace(
        scope_file=None, port=None, allow_private_addresses=False,
        authorization_manifest=str(manifest_path), allow_state_changing_methods=False,
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(AssertionError("DNS in preview")))
    out = _scope_preview(args, "https://example.com/")
    assert out["network_contact"] is False
    assert out["allowed_methods"] == ["GET", "HEAD", "OPTIONS"]

def test_network_audit_is_redacted_and_attributable():
    cfg = ScanConfig(target="https://example.com")
    cfg.test_reason = "approved boundary validation"
    cfg.scope.allowed_hosts = ["example.com"]
    cfg.scope.allowed_ports = [443]
    client = SafeHttpClient(cfg)
    result = client.dry_run("GET", "https://example.com/api?token=SHOULD-NOT-APPEAR", reason="preview")
    assert result["network_contact"] is False
    event = client.audit_events[-1]
    assert event["schema"] == "ersec-network-audit/1"
    assert event["test_reason"] == "approved boundary validation"
    assert "SHOULD-NOT-APPEAR" not in json.dumps(event)
    assert "SHOULD-NOT-APPEAR" not in event["target"]
