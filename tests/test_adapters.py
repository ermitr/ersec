"""
Rigor Tests for Target Adapters.
"""
import pytest
from ersec.adapters.juiceshop import JuiceShopAdapter

def test_juiceshop_normalization():
    adapter = JuiceShopAdapter("http://localhost:3000")
    assert adapter.normalize_path("/api/products") == "/api/v1/api/products"
    assert adapter.normalize_path("/rest/admin/users") == "/rest/admin/users"

def test_juiceshop_url_generation():
    adapter = JuiceShopAdapter("http://localhost:3000")
    assert adapter.get_full_url("/api/products") == "http://localhost:3000/api/v1/api/products"

def test_juiceshop_headers():
    adapter = JuiceShopAdapter("http://localhost:3000")
    headers = adapter.get_session_headers("token123")
    assert headers["Cookie"] == "session=token123"
    assert "User-Agent" in headers
