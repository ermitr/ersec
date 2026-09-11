"""
Target Adapter Framework for ERSEC.
Allows the assurance engine to interact with diverse targets (Fixtures, Dockerized Apps, Cloud APIs)
without changing the core logic.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from pathlib import Path

class TargetAdapter(ABC):
    """
    Base class for all target adapters.
    Ensures that the core engine can request tokens, normalize URLs, and
    manage target-specific state.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    @abstractmethod
    def get_auth_token(self, identity_id: str) -> Optional[str]:
        """
        Retrieve or generate a session token for a specific identity.
        """
        pass

    @abstractmethod
    def normalize_path(self, path: str) -> str:
        """
        Convert a logical path (e.g., '/api/orders') to a target-specific URL.
        """
        pass

    def get_full_url(self, path: str) -> str:
        """Return the absolute URL for a given path."""
        return f"{self.base_url}{self.normalize_path(path)}"
