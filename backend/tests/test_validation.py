import pytest
from app.core.target_validation import validate_and_normalize_target

def test_valid_domains():
    valid_cases = [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  example.com  ", "example.com"),
        ("example.com.", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example")
    ]
    for target, expected in valid_cases:
        res = validate_and_normalize_target(target)
        assert res["valid"] is True
        assert res["type"] == "domain"
        assert res["normalized"] == expected

def test_valid_ipv4():
    valid_cases = [
        "8.8.8.8",
        "1.1.1.1"
    ]
    for target in valid_cases:
        res = validate_and_normalize_target(target)
        assert res["valid"] is True
        assert res["type"] == "ipv4"
        assert res["normalized"] == target

def test_invalid_targets():
    invalid_cases = [
        "",
        "   ",
        "localhost",
        "server01",
        "example..com",
        "-example.com",
        "example-.com",
        "http://example.com",
        "https://example.com",
        "example.com/path",
        "example.com:8080",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "256.256.256.256",
        "999.1.1.1"
    ]
    for target in invalid_cases:
        with pytest.raises(ValueError):
            validate_and_normalize_target(target)
