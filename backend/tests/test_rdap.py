import pytest
import time
from unittest.mock import patch
import app.intelligence.rdap as rdap_module
from app.intelligence.rdap import collect_domain_rdap, _get_iana_bootstrap

@pytest.fixture(autouse=True)
def clear_cache():
    rdap_module._IANA_BOOTSTRAP_CACHE.clear()
    rdap_module._IANA_BOOTSTRAP_TIMESTAMP = 0.0

def test_successful_rdap():
    def mock_get(url, **kwargs):
        if "data.iana.org" in str(url):
            return {"status": "success", "data": {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}}
        return {"status": "success", "source": str(url), "data": {
            "handle": "12345",
            "events": [
                {"eventAction": "expiration", "eventDate": "2025-09-14T04:00:00Z"},
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                {"eventAction": "last update of rdap database", "eventDate": "2023-01-01T00:00:00Z"}
            ],
            "entities": [
                {"handle": "REG-123", "roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]},
                {"handle": "ORG-123", "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Inc."], ["kind", {}, "text", "org"]]]},
                {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "John Doe"], ["kind", {}, "text", "individual"]]]}
            ],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM."}, {"ldhName": "ns1.example.com"}],
            "status": ["clientTransferProhibited"]
        }}

    with patch('app.intelligence.rdap._fetch_rdap', side_effect=mock_get):
        res = collect_domain_rdap("example.com")
        assert res["status"] == "success"
        assert res["handle"] == "12345"
        assert res["registrar"]["name"] == "Example Registrar"

def test_rdap_statuses():
    def mock_get(url, **kwargs):
        if "data.iana.org" in str(url):
            return {"status": "success", "data": {"services": [[["com"], ["https://rdap.com/"]]]}}
        if "404" in str(url): return {"status": "not_found"}
        if "429" in str(url): return {"status": "rate_limited"}
        if "500" in str(url): return {"status": "error"}
        if "invalid" in str(url): return {"status": "error"}
        return {"status": "error"}

    with patch('app.intelligence.rdap._fetch_rdap', side_effect=mock_get):
        assert collect_domain_rdap("404.com")["status"] == "not_found"
        assert collect_domain_rdap("429.com")["status"] == "rate_limited"
        assert collect_domain_rdap("500.com")["status"] == "error"

def test_rdap_redirects():
    def mock_get(url, **kwargs):
        url = str(url)
        if "data.iana.org" in url:
            return {"status": "success", "data": {"services": [[["com"], ["https://rdap.com/"]]]}}
        if "/domain/redir.com" in url:
            return {"status": "success", "source": "https://rdap.com/domain/redir2.com", "data": {"handle": "DONE"}}
        if "/domain/badredir.com" in url:
            return {"status": "error"}
        if "/domain/loop.com" in url:
            return {"status": "error"}
        return {"status": "not_found"}

    with patch('app.intelligence.rdap._fetch_rdap', side_effect=mock_get):
        res = collect_domain_rdap("redir.com")
        assert res["status"] == "success"
        res = collect_domain_rdap("badredir.com")
        assert res["status"] == "error"

def test_cache_behavior():
    call_count = 0
    def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        return {"status": "success", "data": {"services": [[["com"], ["https://rdap.com/"]]]}}

    with patch('app.intelligence.rdap._fetch_rdap', side_effect=mock_get):
        _get_iana_bootstrap()
        assert call_count == 1
        _get_iana_bootstrap()
        assert call_count == 1
        rdap_module._IANA_BOOTSTRAP_TIMESTAMP -= 90000
        _get_iana_bootstrap()
        assert call_count == 2
