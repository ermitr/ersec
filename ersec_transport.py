"""Transport boundary adapters for ERSEC's modular migration.

The adapter does not create new probing capabilities; it makes existing
scope checks explicit and reusable by verification/integration code.
"""
from __future__ import annotations
from typing import Any, Mapping
from ersec_ledger import SecurityDecisionLedger

class TransportBoundaryError(RuntimeError):
    pass

class ScopedTransportClient:
    def __init__(self, client: Any, scope_checker, allowed_methods, ledger: SecurityDecisionLedger | None = None):
        self._client = client
        self._scope_checker = scope_checker
        self._allowed_methods = {str(m).upper() for m in allowed_methods}
        self._ledger = ledger

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        normalized_method = str(method).upper()
        if normalized_method not in self._allowed_methods:
            reason = f"method not allowed by transport boundary: {normalized_method}"
            if self._ledger:
                self._ledger.log_decision(normalized_method, url, "BLOCKED", reason)
            raise TransportBoundaryError(reason)

        # Default safety settings
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("verify", True)

        max_redirects = kwargs.pop("max_redirects", 5)
        redirects_followed = 0
        current_url = url
        current_method = normalized_method

        while True:
            allowed, reason = self._scope_checker(current_method, current_url)
            if not allowed:
                if self._ledger:
                    self._ledger.log_decision(current_method, current_url, "BLOCKED", reason)
                raise TransportBoundaryError(f"request denied by transport boundary: {reason or 'unknown'}")

            if self._ledger:
                self._ledger.log_decision(current_method, current_url, "ALLOWED", "scope_verified")

            response = self._client.request(current_method, current_url, **kwargs)

            if getattr(response, "is_redirect", False):
                redirects_followed += 1
                if redirects_followed > max_redirects:
                    if self._ledger:
                        self._ledger.log_decision(current_method, current_url, "BLOCKED", "too_many_redirects")
                    raise TransportBoundaryError("too many redirects")

                from urllib.parse import urljoin
                next_url = response.headers.get("Location")
                if not next_url:
                    break

                current_url = urljoin(current_url, next_url)
                current_method = "GET"
                continue

            break

        return response
