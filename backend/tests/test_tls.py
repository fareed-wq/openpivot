import pytest
import socket
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from app.intelligence.tls import collect_tls_intelligence, _parse_certificate
from app.core.network_safety import NetworkSafetyError
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_mock_cert(expired=False):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])
    
    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=10)
        not_after = now - timedelta(days=5)
    else:
        not_before = now - timedelta(days=5)
        not_after = now + timedelta(days=10)
        
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"example.com."),
            x509.DNSName(u"WWW.EXAMPLE.COM"),
            x509.DNSName(u"example.com")
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.DER)

@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls._connect_and_get_cert")
def test_successful_tls_collection(mock_connect, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    mock_connect.return_value = (generate_mock_cert(), "TLSv1.3", "TLS_AES_256_GCM_SHA384", None)
    
    res = collect_tls_intelligence("example.com")
    
    assert res["status"] == "success"
    assert res["peer_ip"] == "8.8.8.8"
    assert res["port"] == 443
    assert res["tls_version"] == "TLSv1.3"
    assert res["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert res["verification"]["status"] == "verified"
    
    cert = res["certificate"]
    assert cert["subject"] == "commonName=example.com"
    assert cert["issuer"] == "commonName=example.com"
    assert cert["currently_valid"] is True
    assert cert["days_until_expiry"] == 9
    assert cert["san_dns"] == ["example.com", "www.example.com"]

@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls._connect_and_get_cert")
def test_verification_failure_fallback(mock_connect, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    
    def side_effect(ip, domain, verify):
        if verify:
            return None, None, None, "certificate verify failed"
        else:
            return generate_mock_cert(expired=True), "TLSv1.2", "AES256-SHA", None
            
    mock_connect.side_effect = side_effect
    
    res = collect_tls_intelligence("example.com")
    assert res["status"] == "partial"
    assert res["verification"]["status"] == "failed"
    assert res["verification"]["reason"] == "certificate verify failed"
    assert res["certificate"]["currently_valid"] is False
    assert res["certificate"]["days_until_expiry"] < 0

@patch("app.intelligence.tls.resolve_safe_addresses")
def test_network_safety_blocked(mock_resolve):
    mock_resolve.side_effect = NetworkSafetyError("No globally routable public addresses found")
    res = collect_tls_intelligence("example.com")
    assert res["status"] == "blocked"

@patch("app.intelligence.tls.resolve_safe_addresses")
def test_dns_resolution_failure(mock_resolve):
    mock_resolve.side_effect = NetworkSafetyError("DNS resolution failed")
    res = collect_tls_intelligence("invalid.domain")
    assert res["status"] == "unavailable"

@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls._connect_and_get_cert")
def test_socket_timeout(mock_connect, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    mock_connect.side_effect = socket.timeout()
    res = collect_tls_intelligence("example.com")
    assert res["status"] == "timeout"

@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls._connect_and_get_cert")
def test_multi_ip_failover(mock_connect, mock_resolve):
    mock_resolve.return_value = ["198.51.100.1", "203.0.113.1"]
    
    # First IP fails with timeout, second succeeds
    def side_effect(ip, domain, verify):
        if ip == "198.51.100.1":
            raise socket.timeout()
        return generate_mock_cert(), "TLSv1.3", "TLS_AES", None
        
    mock_connect.side_effect = side_effect
    
    res = collect_tls_intelligence("example.com")
    assert res["status"] == "success"
    assert res["peer_ip"] == "203.0.113.1"
    
@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls.socket.socket")
@patch("app.intelligence.tls.ssl.create_default_context")
def test_no_second_dns_resolution(mock_ssl_ctx, mock_socket, mock_resolve):
    mock_resolve.return_value = ["93.184.216.34"]
    
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance
    
    mock_ctx_instance = MagicMock()
    mock_ssl_ctx.return_value = mock_ctx_instance
    
    mock_ssock = MagicMock()
    mock_ctx_instance.wrap_socket.return_value = mock_ssock
    
    mock_ssock.getpeercert.return_value = generate_mock_cert()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("AES",)
    
    res = collect_tls_intelligence("example.com")
    
    # Assert connection goes to IP, not domain
    mock_sock_instance.connect.assert_called_with(("93.184.216.34", 443))
    # Assert SNI uses domain
    mock_ctx_instance.wrap_socket.assert_called_with(mock_sock_instance, server_hostname="example.com")

@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls._connect_and_get_cert")
def test_connection_refused(mock_connect, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    mock_connect.side_effect = ConnectionRefusedError()
    res = collect_tls_intelligence("example.com")
    assert res["status"] == "unavailable"

@patch("app.intelligence.tls.resolve_safe_addresses")
@patch("app.intelligence.tls._connect_and_get_cert")
def test_malformed_certificate(mock_connect, mock_resolve):
    mock_resolve.return_value = ["8.8.8.8"]
    mock_connect.return_value = (b"invalid_der_data", "TLSv1.3", "AES", None)
    res = collect_tls_intelligence("example.com")
    assert res["status"] == "error"

