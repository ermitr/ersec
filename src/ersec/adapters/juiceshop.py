"""
Juice Shop Target Adapter.
Implements the specific logic needed to interact with the OWASP Juice Shop,
including its unique session management and endpoint patterns.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from ersec.adapters.base import TargetAdapter

class JuiceShopAdapter(TargetAdapter):
    """
    Adapter for OWASP Juice Shop.
    Handles session cookies and normalizing Juice Shop's specific API paths.
    """

    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.session_cookie_name = "session"

    def get_auth_token(self, identity_id: str) -> Optional[str]:
        """
        In Juice Shop, 'tokens' are usually session cookies.
        This method would normally interface with a vault or session manager.
        """
        # For this implementation, we assume the identity_id is the session token itself.
        return identity_id

    def normalize_path(self, path: str) -> str:
        """
        Juice Shop often uses /rest/admin or /api patterns.
        This ensures paths are normalized to the Juice Shop REST API.
        """
        if path.startswith("/api") and not path.startswith("/api/v1"):
            return f"/api/v1{path}"
        return path

    def get_session_headers(self, token: str) -> Dict[str, str]:
        """Return the specific headers required for Juice Shop session auth."""
        return {
            "Cookie": f"{self.session_cookie_name}={token}",
            "User-Agent": "ERSEC-Assurance-Agent/1.0",
            "Accept": "application/json"
        }
