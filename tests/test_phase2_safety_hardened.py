import pytest
from ersec_transport import ScopedTransportClient, TransportBoundaryError
from unittest.mock import MagicMock, patch
import requests

def test_read_only_default_methods():
    # Mock a client and scope checker that allows only GET
    mock_client = MagicMock()
    scope_checker = lambda m, u: (True, "")
    client = ScopedTransportClient(mock_client, scope_checker, ["GET", "HEAD", "OPTIONS"])

    # Mock a non-redirect response
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_client.request.return_value = mock_resp

    # GET should work
    client.request("GET", "http://example.com")

    # POST should be blocked by transport boundary
    with pytest.raises(TransportBoundaryError, match="method not allowed by transport boundary: POST"):
        client.request("POST", "http://example.com")

def test_redirect_revalidation():
    mock_client = MagicMock()
    # First request OK, second (redirect) NOT OK
    scope_checks = [ (True, ""), (False, "redirect_denied") ]
    def scope_checker(m, u):
        return scope_checks.pop(0) if scope_checks else (False, "no_more_checks")

    client = ScopedTransportClient(mock_client, scope_checker, ["GET"])

    # Mock a redirect response
    mock_resp = MagicMock()
    mock_resp.is_redirect = True
    mock_resp.headers = {"Location": "http://malicious.com"}
    mock_client.request.return_value = mock_resp

    with pytest.raises(TransportBoundaryError, match="request denied by transport boundary: redirect_denied"):
        client.request("GET", "http://example.com")

def test_timeout_enforcement():
    mock_client = MagicMock()
    scope_checker = lambda m, u: (True, "")
    client = ScopedTransportClient(mock_client, scope_checker, ["GET"])

    # Mock a non-redirect response
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_client.request.return_value = mock_resp

    client.request("GET", "http://example.com")
    # Verify that timeout=30 was passed to the underlying request
    args, kwargs = mock_client.request.call_args
    assert kwargs["timeout"] == 30

def test_tls_verification_default():
    mock_client = MagicMock()
    scope_checker = lambda m, u: (True, "")
    client = ScopedTransportClient(mock_client, scope_checker, ["GET"])

    # Mock a non-redirect response
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_client.request.return_value = mock_resp

    client.request("GET", "https://example.com")
    args, kwargs = mock_client.request.call_args
    assert kwargs["verify"] is True
