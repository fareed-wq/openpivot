import pytest
import socket
from unittest.mock import patch
from app.core.network_safety import resolve_safe_addresses, NetworkSafetyError, _is_safe_ip

def test_safe_ips():
    assert _is_safe_ip("8.8.8.8")
    assert _is_safe_ip("2606:4700:4700::1111")
    
    assert not _is_safe_ip("127.0.0.1")
    assert not _is_safe_ip("10.0.0.1")
    assert not _is_safe_ip("172.16.0.1")
    assert not _is_safe_ip("192.168.1.1")
    assert not _is_safe_ip("169.254.1.1")
    assert not _is_safe_ip("::1")
    assert not _is_safe_ip("fc00::1")
    assert not _is_safe_ip("fe80::1")

def test_resolve_safe_addresses_success():
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2606:4700:4700::1111", 0, 0, 0)),
        ]
        ips = resolve_safe_addresses("example.com")
        assert ips == ["8.8.8.8", "2606:4700:4700::1111"]

def test_resolve_safe_addresses_blocked():
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))
        ]
        with pytest.raises(NetworkSafetyError, match="No globally routable public addresses found"):
            resolve_safe_addresses("example.com")

def test_resolve_safe_addresses_dedup_and_bound():
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("9.9.9.9", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("4.4.4.4", 0)),
        ]
        ips = resolve_safe_addresses("example.com")
        assert ips == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        assert len(ips) == 3

def test_resolve_safe_addresses_failure():
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.side_effect = socket.gaierror("Name or service not known")
        with pytest.raises(NetworkSafetyError, match="DNS resolution failed"):
            resolve_safe_addresses("example.com")
