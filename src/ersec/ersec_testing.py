"""Controlled local testing fixtures for ERSEC integration tests.

Fixtures bind only to loopback by default and perform deterministic, harmless
responses. They are intended for tests and benchmark development, not target
interaction.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Mapping


@dataclass
class ControlledHTTPFixture:
    server: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def start_fixture(handler: Callable[[BaseHTTPRequestHandler], None] | None = None) -> ControlledHTTPFixture:
    class Handler(BaseHTTPRequestHandler):
        def _respond(self) -> None:
            if handler is not None:
                handler(self)
                return
            body = json.dumps({"ok": True, "fixture": "ersec-controlled-http"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._respond()

        def do_HEAD(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            self._respond()

        def log_message(self, *_args) -> None:
            pass

    class ReusableThreadingHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = ReusableThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return ControlledHTTPFixture(server=server, thread=thread, base_url=f"http://{host}:{port}")

@dataclass
class MultiTenantAuthorizationFixture:
    """Loopback-only API fixture with deterministic cross-tenant behavior."""
    fixture: ControlledHTTPFixture
    vulnerable: bool
    closed: bool = False
    residual_objects: int = 0

    @property
    def base_url(self) -> str:
        return self.fixture.base_url

    def lifecycle_status(self) -> Dict[str, Any]:
        return {
            "started": True,
            "closed": self.closed,
            "cleanup_verified": self.closed and self.residual_objects == 0,
            "residual_objects": self.residual_objects,
        }

    def close(self) -> None:
        if self.closed:
            return
        self.fixture.close()
        self.closed = True


def start_multitenant_authorization_fixture(*, vulnerable: bool = True) -> MultiTenantAuthorizationFixture:
    """Start a harmless local API fixture for authorization assurance tests.

    The caller supplies an identity through ``X-ERSEC-Identity``. The vulnerable
    mode intentionally returns a tenant-A order to tenant-B users so the
    assurance engine has deterministic ground truth. No state is modified.
    """
    import json as _json
    orders = {
        "order-tenant-a": {"id": "order-tenant-a", "tenant": "tenant_a", "amount": 125, "secret_note": "TENANT_A_ONLY"},
        "order-tenant-b": {"id": "order-tenant-b", "tenant": "tenant_b", "amount": 90, "secret_note": "TENANT_B_ONLY"},
    }
    identities = {
        "tenant_a_user": "tenant_a",
        "tenant_b_user": "tenant_b",
        "tenant_a_support": "tenant_a_support",
        "administrator": "global",
        "anonymous": "",
        "revoked_tenant_a_user": "tenant_a",
    }

    def handler(req: BaseHTTPRequestHandler) -> None:
        from urllib.parse import urlparse
        parsed = urlparse(req.path)
        parts = [p for p in parsed.path.split("/") if p]
        identity = req.headers.get("X-ERSEC-Identity", "anonymous")
        actor_tenant = identities.get(identity, "")
        # Explicit read-only authorization test endpoints.
        if parts[:2] == ["api", "admin"] and len(parts) == 3 and parts[2] == "summary":
            allowed = identity == "administrator"
            if vulnerable and identity == "tenant_a_user":
                allowed = True
            exposed = {"id": "admin-summary", "scope": "global"} if allowed else {"error": "forbidden"}
            body = _json.dumps(exposed).encode("utf-8")
            req.send_response(200 if allowed else 403)
        elif len(parts) == 3 and parts[:2] == ["api", "orders"] and parts[2] == "order-obscured":
            # Deliberately ambiguous: successful transport response, but no structured
            # fields are observable. This validates observation_unavailable semantics.
            allowed = identity in {"tenant_a_user", "tenant_a_support", "administrator"}
            body = b"redacted" if allowed else _json.dumps({"error": "forbidden"}).encode("utf-8")
            req.send_response(200 if allowed else 403)
            req.send_header("Content-Type", "text/plain" if allowed else "application/json")
        elif len(parts) == 4 and parts[:3] == ["api", "v1", "orders"]:
            order = orders.get(parts[3])
            if order is None:
                req.send_response(404); req.end_headers(); return
            if identity == "revoked_tenant_a_user":
                allowed = vulnerable
            else:
                allowed = actor_tenant == "global" or actor_tenant == order["tenant"] or (identity == "tenant_a_support" and order["tenant"] == "tenant_a")
            if vulnerable and identity == "tenant_b_user" and order["tenant"] == "tenant_a":
                allowed = True
            exposed = dict(order) if allowed else {"error": "forbidden"}
            if identity == "tenant_a_support" and not vulnerable:
                exposed.pop("secret_note", None)
            body = _json.dumps(exposed).encode("utf-8")
            req.send_response(200 if allowed else (401 if identity == "revoked_tenant_a_user" else 403))
        elif len(parts) == 3 and parts[:2] == ["api", "orders"]:
            order = orders.get(parts[2])
            if order is None:
                req.send_response(404); req.end_headers(); return
            if identity == "revoked_tenant_a_user":
                allowed = vulnerable
            else:
                allowed = actor_tenant == "global" or actor_tenant == order["tenant"] or (identity == "tenant_a_support" and order["tenant"] == "tenant_a")
            if vulnerable and identity == "tenant_b_user" and order["tenant"] == "tenant_a":
                exposed = dict(order); allowed = True
            else:
                exposed = dict(order) if allowed else {"error": "forbidden"}
            if identity == "tenant_a_support" and not vulnerable:
                exposed.pop("secret_note", None)
            body = _json.dumps(exposed).encode("utf-8")
            req.send_response(200 if allowed else (401 if identity == "revoked_tenant_a_user" else 403))
        else:
            req.send_response(404); req.end_headers(); return
        req.send_header("Content-Type", "application/json")
        req.send_header("Content-Length", str(len(body)))
        req.end_headers()
        req.wfile.write(body)
        return

    fixture = start_fixture(handler)
    return MultiTenantAuthorizationFixture(fixture=fixture, vulnerable=vulnerable)
