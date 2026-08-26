import pytest
import dns.resolver
import dns.reversename
import dns.exception
from unittest.mock import patch, MagicMock
from app.intelligence.asn import (
    collect_asn_intelligence_from_ip, 
    normalize_asn,
    _get_iana_asn_bootstrap
)

@pytest.fixture(autouse=True)
def clear_caches():
    import app.intelligence.asn as asn_module
    asn_module._IANA_ASN_BOOTSTRAP_CACHE = []
    asn_module._IANA_ASN_BOOTSTRAP_TIMESTAMP = 0.0
    yield

def test_asn_normalization():
    assert normalize_asn("15169") == 15169
    assert normalize_asn("AS15169") == 15169
    assert normalize_asn("as15169") == 15169
    assert normalize_asn("  as15169  ") == 15169
    assert normalize_asn("abc") is None
    assert normalize_asn("") is None
    assert normalize_asn("-1") is None
    assert normalize_asn("0") is None
    assert normalize_asn("4294967295") is None

@patch("app.intelligence.asn.httpx.Client.get")
@patch("app.intelligence.asn._fetch_rdap")
@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_successful_asn_flow(mock_resolve, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["15169"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    mock_rdap.return_value = {
        "status": "success",
        "source": "https://rdap.arin.net/registry/autnum/15169",
        "data": {
            "handle": "AS15169",
            "name": "GOOGLE",
            "startAutnum": 15169,
            "endAutnum": 15169,
            "country": "US",
            "type": "DIRECT ALLOCATION",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00-05:00"}],
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
    
    class FakeAnswer:
        def __str__(self): return '"15169 | 8.8.8.0/24 | US | arin | 2014-03-14"'
    mock_resolve.return_value = [FakeAnswer()]
    
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "success"
    assert res["origin"]["asns"] == [15169]
    assert res["origin"]["prefix"] == "8.8.8.0/24"
    assert res["asn"]["number"] == 15169
    assert res["asn"]["organization"]["name"] == "Google LLC"

@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_cymru_dns_failures(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NoAnswer()
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "not_found"
    
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "not_found"
    
    mock_resolve.side_effect = dns.exception.Timeout()
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "timeout"
    
    mock_resolve.side_effect = Exception("Unknown")
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "error"

@patch("app.intelligence.asn.httpx.Client.get")
@patch("app.intelligence.asn._fetch_rdap")
@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_rdap_failures(mock_resolve, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["15169"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    class FakeAnswer:
        def __str__(self): return '"15169 | 8.8.8.0/24 | US | arin | 2014-03-14"'
    mock_resolve.return_value = [FakeAnswer()]
    
    # RDAP 404
    mock_rdap.return_value = {"status": "not_found"}
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "partial"
    
    # RDAP Timeout
    mock_rdap.return_value = {"status": "timeout"}
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "partial"

@patch("app.intelligence.asn.httpx.Client.get")
def test_bootstrap_logic(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [
            [["1-100000"], ["https://rdap.arin.net/registry/"]],
            [["15169"], ["https://rdap.specific.net/registry/"]]
        ]}
    )
    
    bootstrap = _get_iana_asn_bootstrap()
    assert len(bootstrap) == 2
    # Verify the most specific range is chosen
    # Since 15169 has range length 0 and 1-100000 has 99999, it should pick the exact match
    
    best_range_len = float('inf')
    base_url = None
    for start, end, url in bootstrap:
        if start <= 15169 <= end:
            range_len = end - start
            if range_len < best_range_len:
                best_range_len = range_len
                base_url = url
                
    assert base_url == "https://rdap.specific.net/registry/"

import pytest
import dns.resolver
from unittest.mock import patch, MagicMock
from app.intelligence.asn import collect_asn_intelligence_from_ip

@patch("app.intelligence.asn.httpx.Client.get")
@patch("app.intelligence.asn._fetch_rdap")
@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_multiple_origin_asns(mock_resolve, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["15169-15170"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    mock_rdap.return_value = {"status": "success", "source": "src", "data": {}}
    
    class FakeAnswer:
        def __str__(self): return '"15169 15170 | 8.8.8.0/24 | US | arin | 2014-03-14"'
    mock_resolve.return_value = [FakeAnswer()]
    
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "success"
    assert res["origin"]["asns"] == [15169, 15170]

@patch("app.intelligence.asn.httpx.Client.get")
@patch("app.intelligence.asn._fetch_rdap")
@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_privacy_filtering(mock_resolve, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["15169"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    mock_rdap.return_value = {
        "status": "success",
        "source": "src",
        "data": {
            "entities": [
                {
                    "roles": ["administrative"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "John Doe"], ["kind", {}, "text", "individual"]]]
                },
                {
                    "roles": ["registrant"],
                    "handle": "GOOGL",
                    "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"], ["kind", {}, "text", "org"]]]
                }
            ]
        }
    }
    
    class FakeAnswer:
        def __str__(self): return '"15169 | 8.8.8.0/24 | US | arin | 2014-03-14"'
    mock_resolve.return_value = [FakeAnswer()]
    
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "success"
    assert res["asn"]["organization"]["name"] == "Google LLC"
    
    import json
    res_str = json.dumps(res)
    assert "John Doe" not in res_str

import pytest
from app.intelligence.asn import normalize_asn, collect_asn_intelligence_from_ip
from unittest.mock import patch, MagicMock

def test_asn_validation_boundaries():
    assert normalize_asn("64495") == 64495
    assert normalize_asn("64496") is None
    assert normalize_asn("64511") is None
    assert normalize_asn("64512") is None
    assert normalize_asn("65534") is None
    assert normalize_asn("65535") is None
    assert normalize_asn("65536") is None
    assert normalize_asn("65551") is None
    assert normalize_asn("65552") == 65552
    assert normalize_asn("4199999999") == 4199999999
    assert normalize_asn("4200000000") is None
    assert normalize_asn("4294967294") is None
    assert normalize_asn("4294967295") is None
    assert normalize_asn("0") is None
    assert normalize_asn("23456") is None

@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_cymru_prefix_validation(mock_resolve):
    # Malformed prefix -> discarded
    class FakeAnswer1:
        def __str__(self): return '"15169 | 8.8.8.0/abc | US | arin"'
    mock_resolve.return_value = [FakeAnswer1()]
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["origin"]["prefix"] is None
    
    # Prefix not containing IP -> discarded
    class FakeAnswer2:
        def __str__(self): return '"15169 | 9.9.9.0/24 | US | arin"'
    mock_resolve.return_value = [FakeAnswer2()]
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["origin"]["prefix"] is None

    # Valid prefix
    class FakeAnswer3:
        def __str__(self): return '"15169 | 8.8.8.0/24 | US | arin"'
    mock_resolve.return_value = [FakeAnswer3()]
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["origin"]["prefix"] == "8.8.8.0/24"

@patch("app.intelligence.asn.httpx.Client.get")
@patch("app.intelligence.asn._fetch_rdap")
@patch("app.intelligence.asn.dns.resolver.Resolver.resolve")
def test_asn_rdap_normalization_error(mock_resolve, mock_rdap, mock_get):
    mock_get.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"services": [[["15169"], ["https://rdap.arin.net/registry/"]]]}
    )
    
    # Start and end autnum do not include the queried ASN
    mock_rdap.return_value = {
        "status": "success",
        "source": "src",
        "data": {
            "startAutnum": 9999,
            "endAutnum": 9999
        }
    }
    
    class FakeAnswer:
        def __str__(self): return '"15169 | 8.8.8.0/24 | US | arin"'
    mock_resolve.return_value = [FakeAnswer()]
    
    res = collect_asn_intelligence_from_ip("8.8.8.8")
    assert res["status"] == "partial"
    assert res.get("asn") is None
