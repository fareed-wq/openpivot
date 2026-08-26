import pytest
import ipaddress
import dns.resolver
import dns.reversename
import dns.exception
from unittest.mock import patch, MagicMock
from app.intelligence.ip import collect_ip_intelligence, _IANA_IPV4_BOOTSTRAP_CACHE

@pytest.fixture(autouse=True)
def clear_caches():
    import app.intelligence.ip as ip_module
    ip_module._IANA_IPV4_BOOTSTRAP_CACHE = []
    ip_module._IANA_IPV4_BOOTSTRAP_TIMESTAMP = 0.0
    yield

def test_blocked_ips():
    assert collect_ip_intelligence("10.0.0.1")["status"] == "blocked"
    assert collect_ip_intelligence("127.0.0.1")["status"] == "blocked"
    assert collect_ip_intelligence("169.254.1.1")["status"] == "blocked"
    assert collect_ip_intelligence("0.0.0.0")["status"] == "blocked"
    assert collect_ip_intelligence("256.256.256.256")["status"] == "error"
    assert collect_ip_intelligence("2001:db8::1")["status"] == "blocked"

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_successful_ip(mock_dns, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    mock_rdap.return_value = {
        "status": "success",
        "source": "https://rdap.arin.net/registry/ip/8.8.8.8",
        "data": {
            "handle": "NET-8-8-8-0-24",
            "name": "GOOGLE",
            "startAddress": "8.8.8.0",
            "endAddress": "8.8.8.255",
            "ipVersion": "v4",
            "type": "DIRECT ALLOCATION",
            "country": "US",
            "parentHandle": "NET-8-0-0-0-1",
            "status": ["active", "active"],
            "events": [{"eventAction": "registration", "eventDate": "2014-03-14T16:52:05-04:00"}],
            "entities": [{
                "roles": ["registrant"],
                "handle": "GOOGL-2",
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Google LLC"],
                        ["kind", {}, "text", "org"]
                    ]
                ]
            }]
        }
    }
    
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    
    res = collect_ip_intelligence("8.8.8.8")
    assert res["status"] == "success"
    assert res["rdap"]["handle"] == "NET-8-8-8-0-24"
    assert res["rdap"]["name"] == "GOOGLE"
    assert res["rdap"]["network_prefixes"] == ["8.8.8.0/24"]
    assert res["rdap"]["organization"]["name"] == "Google LLC"
    assert res["reverse_dns"]["status"] == "success"
    assert res["reverse_dns"]["hostname"] == "dns.google"

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_cidr_fallback(mock_dns, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    mock_rdap.return_value = {
        "status": "success",
        "source": "https://rdap.arin.net/registry/ip/8.8.8.8",
        "data": {
            "startAddress": "8.8.8.0",
            "endAddress": "8.8.8.255",
            "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}]
        }
    }
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    
    res = collect_ip_intelligence("8.8.8.8")
    assert res["rdap"]["network_prefixes"] == ["8.8.8.0/24"]

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_failure_isolation(mock_dns, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    # RDAP fail, PTR success -> partial
    mock_rdap.return_value = {"status": "timeout"}
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    assert collect_ip_intelligence("8.8.8.8")["status"] == "partial"
    
    # RDAP success, PTR timeout -> partial
    mock_rdap.return_value = {"status": "success", "source": "x", "data": {}}
    mock_dns.return_value = {"status": "timeout"}
    assert collect_ip_intelligence("8.8.8.8")["status"] == "partial"
    
    # Both fail -> timeout
    mock_rdap.return_value = {"status": "timeout"}
    mock_dns.return_value = {"status": "timeout"}
    assert collect_ip_intelligence("8.8.8.8")["status"] == "timeout"
    
    # RDAP success, PTR no_answer -> success
    mock_rdap.return_value = {"status": "success", "source": "x", "data": {}}
    mock_dns.return_value = {"status": "no_answer"}
    assert collect_ip_intelligence("8.8.8.8")["status"] == "success"

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_rdap_unsupported(mock_dns, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": []}
    )
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    res = collect_ip_intelligence("8.8.8.8")
    assert res["status"] == "partial"

import pytest
import ipaddress
import dns.resolver
import dns.reversename
import dns.exception
import time
from unittest.mock import patch, MagicMock
from app.intelligence.ip import collect_ip_intelligence, _get_iana_ipv4_bootstrap, _IANA_IPV4_BOOTSTRAP_CACHE

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_longest_prefix_match(mock_dns, mock_rdap, mock_get):
    # Mock bootstrap with two overlapping networks: /8 and /24
    # The /24 should be chosen for 8.8.8.8.
    # Put /8 last to prove order independence.
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [
            [["8.8.8.0/24"], ["https://rdap.provider-b/"]],
            [["8.0.0.0/8"], ["https://rdap.provider-a/"]]
        ]}
    )
    
    mock_rdap.return_value = {"status": "success", "source": "https://rdap.provider-b/ip/8.8.8.8", "data": {}}
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    
    res = collect_ip_intelligence("8.8.8.8")
    assert res["status"] == "success"
    # Verify _fetch_rdap was called with Provider B's URL
    mock_rdap.assert_called_once_with("https://rdap.provider-b/ip/8.8.8.8")

@patch("app.intelligence.ip.httpx.Client.get")
def test_https_preference(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [
            [["8.0.0.0/8"], ["http://provider.example/rdap/", "https://provider.example/rdap/"]]
        ]}
    )
    
    bootstrap = _get_iana_ipv4_bootstrap()
    assert bootstrap[0][1] == "https://provider.example/rdap/"

@patch("app.intelligence.ip.httpx.Client.get")
def test_cache_behavior(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    # First call fills cache
    bootstrap = _get_iana_ipv4_bootstrap()
    assert mock_get.call_count == 1
    
    # Second call uses cache
    bootstrap2 = _get_iana_ipv4_bootstrap()
    assert mock_get.call_count == 1
    assert bootstrap == bootstrap2

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_privacy_filtering(mock_dns, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    # Entity contains a person (individual) and an org
    mock_rdap.return_value = {
        "status": "success",
        "source": "https://rdap.arin.net/registry/ip/8.8.8.8",
        "data": {
            "entities": [
                {
                    "roles": ["administrative"],
                    "handle": "PERSON-1",
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "John Doe"],
                            ["kind", {}, "text", "individual"],
                            ["email", {}, "text", "johndoe@example.com"],
                            ["tel", {}, "text", "+1-555-555-5555"]
                        ]
                    ]
                },
                {
                    "roles": ["registrant"],
                    "handle": "GOOGL-2",
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Google LLC"],
                            ["kind", {}, "text", "org"]
                        ]
                    ]
                }
            ]
        }
    }
    
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    
    res = collect_ip_intelligence("8.8.8.8")
    assert res["status"] == "success"
    assert res["rdap"]["organization"]["name"] == "Google LLC"
    # Ensure John Doe is nowhere in the structure
    import json
    res_str = json.dumps(res)
    assert "John Doe" not in res_str
    assert "johndoe@example.com" not in res_str
    assert "555-555-5555" not in res_str

@patch("app.intelligence.ip.httpx.Client.get")
@patch("app.intelligence.ip._fetch_rdap")
@patch("app.intelligence.ip._get_reverse_dns")
def test_rdap_failure_combinations(mock_dns, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    # RDAP 404 + PTR Success
    mock_rdap.return_value = {"status": "not_found"}
    mock_dns.return_value = {"status": "success", "hostname": "dns.google"}
    res = collect_ip_intelligence("8.8.8.8")
    assert res["status"] == "partial"
    
    # Both fail
    mock_rdap.return_value = {"status": "error"}
    mock_dns.return_value = {"status": "error"}
    res = collect_ip_intelligence("8.8.8.8")
    assert res["status"] == "error"
