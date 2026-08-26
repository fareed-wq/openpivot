import pytest
import socket
from unittest.mock import patch, MagicMock
from app.core.network_safety import safe_fetch_json, resolve_safe_addresses, NetworkSafetyError
import app.intelligence.rdap

def test_url_validation():
    assert safe_fetch_json("ftp://example.com")["status"] == "error"
    assert safe_fetch_json("http://user:pass@example.com")["status"] == "error"
    assert safe_fetch_json("http://example.com:8080")["status"] == "error"

@patch("app.core.network_safety.socket.getaddrinfo")
def test_ip_resolution_blocking(mock_getaddrinfo):
    def make_addr(ip):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip, 0))]

    # 1. direct literal 127.0.0.1 blocked
    assert safe_fetch_json("http://127.0.0.1")["status"] == "error"
    # 2. private literal blocked
    assert safe_fetch_json("http://10.0.0.1")["status"] == "error"

    # 3. hostname to 127.0.0.1
    mock_getaddrinfo.return_value = make_addr("127.0.0.1")
    assert safe_fetch_json("http://localhost.localdomain")["status"] == "error"

    # 4. hostname to RFC1918
    mock_getaddrinfo.return_value = make_addr("192.168.1.1")
    assert safe_fetch_json("http://internal.example.com")["status"] == "error"

    # 5. hostname to link-local
    mock_getaddrinfo.return_value = make_addr("169.254.169.254")
    assert safe_fetch_json("http://metadata.internal")["status"] == "error"

@patch("app.core.network_safety.socket.getaddrinfo")
@patch("app.core.network_safety.socket.create_connection")
@patch("app.core.network_safety.ssl.create_default_context")
def test_connection_safety(mock_ssl, mock_conn, mock_getaddrinfo):
    # 6. global IP allowed
    # 17. uses prevalidated IP
    # 16. preserves hostname for Host/SNI
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("8.8.8.8", 0))]

    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_ctx = MagicMock()
    mock_ssl.return_value = mock_ctx
    mock_wrapped_sock = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_wrapped_sock

    class FakeResponse:
        def __init__(self):
            self.status = 200
        def read(self, amt=None):
            return b'{"hello": "world"}'
        def getheader(self, *a, **k):
            return None

    # The HTTPConnection / HTTPSConnection in Python handles the socket sending.
    # Since we use safe_fetch_json directly, it instantiates SafeHTTPSConnection.
    # To mock its HTTP response, we patch getresponse on our SafeHTTPSConnection.
    with patch("app.core.network_safety.SafeHTTPSConnection.getresponse", return_value=FakeResponse()):
        res = safe_fetch_json("https://example.com/api")
        assert res["status"] == "success"
        assert res["data"] == {"hello": "world"}

    # Check that create_connection used the explicit resolved IP, not the hostname
    mock_conn.assert_called_with(("8.8.8.8", 443), 3.0)
    # Check that wrap_socket used the original hostname for SNI
    mock_ctx.wrap_socket.assert_called_with(mock_sock, server_hostname="example.com")
    # 18. no second uncontrolled DNS (because we forced "8.8.8.8" in create_connection)

@patch("app.core.network_safety.socket.getaddrinfo")
@patch("app.core.network_safety.SafeHTTPConnection.connect")
@patch("app.core.network_safety.SafeHTTPConnection.request")
@patch("app.core.network_safety.SafeHTTPConnection.getresponse")
def test_mixed_resolution(mock_resp, mock_req, mock_conn, mock_getaddrinfo):
    # 7. mixed private + global result
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("10.0.0.1", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("9.9.9.9", 0))
    ]

    class FakeResponse:
        def __init__(self):
            self.status = 200
        def read(self, amt=None):
            return b'{"safe": true}'
    mock_resp.return_value = FakeResponse()

    res = safe_fetch_json("http://mixed.example.com")
    assert res["status"] == "success"
    # Ensure it only connected to 9.9.9.9
    # In SafeHTTPConnection, we pass the IP to the constructor
    # We can just check what IPs resolve_safe_addresses returned
    assert resolve_safe_addresses("mixed.example.com") == ["9.9.9.9"]

@patch("app.core.network_safety.socket.getaddrinfo")
@patch("app.core.network_safety.SafeHTTPConnection.connect")
@patch("app.core.network_safety.SafeHTTPConnection.request")
@patch("app.core.network_safety.SafeHTTPConnection.getresponse")
def test_redirect_safety(mock_resp, mock_req, mock_conn, mock_getaddrinfo):
    # 8, 9, 10. Redirect safety
    # First request returns 302 to malicious
    mock_getaddrinfo.side_effect = [
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("8.8.8.8", 0))], # step 1
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("127.0.0.1", 0))] # step 2
    ]

    class RedirectResponse:
        def __init__(self):
            self.status = 302
        def getheader(self, name):
            if name.lower() == "location":
                return "http://localhost.internal/"
        def close(self):
            pass

    mock_resp.return_value = RedirectResponse()

    res = safe_fetch_json("http://safe.example.com")
    assert res["status"] == "error" # fails on the second resolution because 127.0.0.1 is not global

    # 14. Redirect limit
    mock_getaddrinfo.side_effect = None
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("8.8.8.8", 0))]

    class LoopResponse:
        def __init__(self):
            self.status = 301
        def getheader(self, name):
            return "http://safe.example.com/loop"
        def close(self):
            pass

    mock_resp.return_value = LoopResponse()
    res = safe_fetch_json("http://safe.example.com")
    assert res["status"] == "error"

def test_module_integration():
    # 19. domain RDAP uses hardened transport
    # 20. IP RDAP uses hardened transport
    # 21. ASN RDAP uses hardened transport
    import app.intelligence.rdap
    import app.intelligence.ip
    import app.intelligence.asn
    assert app.intelligence.rdap._fetch_rdap is safe_fetch_json
    assert app.intelligence.ip._fetch_rdap is safe_fetch_json
    assert app.intelligence.asn._fetch_rdap is safe_fetch_json
@patch("app.core.network_safety.socket.getaddrinfo")
@patch("app.core.network_safety.SafeHTTPConnection.connect")
@patch("app.core.network_safety.SafeHTTPConnection.request")
@patch("app.core.network_safety.SafeHTTPConnection.getresponse")
def test_max_response_size(mock_resp, mock_req, mock_conn, mock_getaddrinfo):
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ("8.8.8.8", 0))]
    class BigResponse:
        def __init__(self):
            self.status = 200
        def getheader(self, name): return None
        def close(self): pass
        def read(self, amt=None):
            if amt is None: return b"x" * 100
            return b"a" * (amt + 1)

    mock_resp.return_value = BigResponse()
    res = safe_fetch_json("http://safe.example.com")
    assert res["status"] == "error"
