import pytest
import socket
import ssl
import http.client
from unittest.mock import patch, MagicMock
from app.intelligence.http_metadata import collect_http_metadata, _is_safe_redirect_url
from app.core.network_safety import NetworkSafetyError

def test_safe_redirect_urls():
    assert _is_safe_redirect_url("https://example.com/foo")
    assert _is_safe_redirect_url("http://example.com/")
    assert not _is_safe_redirect_url("javascript:alert(1)")
    assert not _is_safe_redirect_url("file:///etc/passwd")
    assert not _is_safe_redirect_url("https://user:pass@example.com/")
    assert not _is_safe_redirect_url("https://example.com:8443/")
    assert not _is_safe_redirect_url("https://example.com:4443/")

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.socket.create_connection")
@patch("app.intelligence.http_metadata.ssl.create_default_context")
def test_successful_https_200(mock_ssl, mock_sock, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    
    mock_conn = MagicMock()
    mock_sock.return_value = mock_conn
    
    mock_ctx = MagicMock()
    mock_ssl.return_value = mock_ctx
    mock_ssock = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssock
    
    class FakeResponse:
        def __init__(self):
            self.status = 200
        def getheader(self, name): return None
        def getheaders(self):
            return [("Content-Type", "text/html"), ("Server", "nginx")]
        def read(self, amt):
            return b"<html><head><title>Test Title</title></head><body></body></html>"
        def close(self): pass
            
    with patch("app.intelligence.http_metadata.SafeHTTPSConnection.getresponse", return_value=FakeResponse()):
        res = collect_http_metadata("example.com")

        assert res["status"] == "success"
        assert res["scheme"] == "https"
        assert res["status_code"] == 200
        assert res["https"]["reachable"] is True
        assert res["https"]["verified"] is True
        assert res["title"] == "Test Title"
        assert res["headers"] == {"content-type": "text/html", "server": "nginx"}
        assert res["peer_ip"] == "8.8.8.8"

        mock_sock.assert_called_with(("8.8.8.8", 443), 4.0)
        mock_ctx.wrap_socket.assert_called_with(mock_conn, server_hostname="example.com")

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
def test_blocked_by_network_safety(mock_resolve):
    mock_resolve.side_effect = NetworkSafetyError("No globally routable public addresses found")
    res = collect_http_metadata("example.com")
    assert res["status"] == "blocked"

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
def test_dns_failure(mock_resolve):
    mock_resolve.side_effect = NetworkSafetyError("DNS resolution failed")
    res = collect_http_metadata("example.com")
    assert res["status"] == "unavailable"

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.socket.create_connection")
def test_timeout(mock_sock, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    mock_sock.side_effect = socket.timeout()
    
    res = collect_http_metadata("example.com")
    assert res["status"] == "timeout"
    assert res["https"]["reachable"] is False

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.ssl.create_default_context")
@patch("app.intelligence.http_metadata.socket.create_connection")
def test_ssl_verification_fallback(mock_sock, mock_ssl_ctx, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    
    mock_ctx_instance = MagicMock()
    mock_ssl_ctx.return_value = mock_ctx_instance
    mock_ctx_instance.wrap_socket.side_effect = ssl.SSLCertVerificationError()
    
    class FakeResponse:
        def __init__(self):
            self.status = 200
        def getheader(self, name): return None
        def getheaders(self): return []
        def read(self, amt): return b""
        def close(self): pass

    with patch("app.intelligence.http_metadata.SafeHTTPConnection.getresponse", return_value=FakeResponse()):
        res = collect_http_metadata("example.com")
        assert res["status"] == "partial"
        assert res["scheme"] == "http"
        assert res["https"]["reachable"] is True
        assert res["https"]["verified"] is False

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.socket.create_connection")
@patch("app.intelligence.http_metadata.ssl.create_default_context")
def test_redirects(mock_ssl_ctx, mock_sock, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    
    class FakeRedirect:
        def __init__(self):
            self.status = 301
        def getheader(self, name): return "https://example.com/login"
        def getheaders(self): return []
        def close(self): pass
        
    class FakeSuccess:
        def __init__(self):
            self.status = 200
        def getheader(self, name): return None
        def getheaders(self): return []
        def read(self, amt): return b""
        def close(self): pass

    responses = [FakeRedirect(), FakeSuccess()]
    
    with patch("app.intelligence.http_metadata.SafeHTTPSConnection.getresponse", side_effect=responses):
        res = collect_http_metadata("example.com")
        assert res["status"] == "success"
        assert len(res["redirects"]) == 1
        assert res["redirects"][0]["status_code"] == 301

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.socket.create_connection")
@patch("app.intelligence.http_metadata.ssl.create_default_context")
def test_bad_redirect_blocked(mock_ssl_ctx, mock_sock, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    
    class FakeRedirect:
        def __init__(self):
            self.status = 302
        def getheader(self, name): return "javascript:alert(1)"
        def getheaders(self): return []
        def close(self): pass
        
    with patch("app.intelligence.http_metadata.SafeHTTPSConnection.getresponse", return_value=FakeRedirect()):
        res = collect_http_metadata("example.com")
        assert res["status"] == "blocked"

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.socket.create_connection")
@patch("app.intelligence.http_metadata.ssl.create_default_context")
def test_mixed_dns_failover(mock_ssl, mock_sock, mock_resolve):
    mock_resolve.return_value = ["198.51.100.1", "203.0.113.1"]
    
    mock_ctx = MagicMock()
    mock_ssl.return_value = mock_ctx
    mock_ctx.wrap_socket.return_value = MagicMock()
    
    def mock_create_connection(address, timeout):
        if address[0] == "198.51.100.1":
            raise socket.timeout()
        return MagicMock()
        
    mock_sock.side_effect = mock_create_connection
    
    class FakeResponse:
        def __init__(self): self.status = 200
        def getheader(self, name): return None
        def getheaders(self): return []
        def read(self, amt): return b""
        def close(self): pass
        
    with patch("app.intelligence.http_metadata.SafeHTTPSConnection.getresponse", return_value=FakeResponse()):
        res = collect_http_metadata("example.com")
        assert res["status"] == "success"
        assert res["peer_ip"] == "203.0.113.1"

@patch("app.intelligence.http_metadata.resolve_safe_addresses")
@patch("app.intelligence.http_metadata.socket.create_connection")
@patch("app.intelligence.http_metadata.ssl.create_default_context")
def test_max_redirects_enforced(mock_ssl, mock_sock, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    
    class FakeRedirect:
        def __init__(self): self.status = 301
        def getheader(self, name): return "https://example.com/loop"
        def getheaders(self): return []
        def close(self): pass
        
    responses = [FakeRedirect()] * 5
    
    with patch("app.intelligence.http_metadata.SafeHTTPSConnection.getresponse", side_effect=responses):
        res = collect_http_metadata("example.com")
        assert res["status"] == "partial"
        assert len(res["redirects"]) == 3
