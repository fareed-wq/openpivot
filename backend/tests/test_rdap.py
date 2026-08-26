import pytest
import time
from unittest.mock import patch, MagicMock
import httpx
import app.intelligence.rdap as rdap_module
from app.intelligence.rdap import collect_domain_rdap, _get_iana_bootstrap

@pytest.fixture(autouse=True)
def clear_cache():
    rdap_module._IANA_BOOTSTRAP_CACHE.clear()
    rdap_module._IANA_BOOTSTRAP_TIMESTAMP = 0.0

def test_successful_rdap():
    def mock_get(url, **kwargs):
        m = MagicMock()
        if "data.iana.org" in str(url):
            m.status_code = 200
            m.json.return_value = {
                "services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]
            }
        else:
            m.status_code = 200
            m.json.return_value = {
                "handle": "12345",
                "events": [
                    {"eventAction": "expiration", "eventDate": "2025-09-14T04:00:00Z"},
                    {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                    {"eventAction": "last update of rdap database", "eventDate": "2023-01-01T00:00:00Z"}
                ],
                "entities": [
                    {
                        "handle": "REG-123",
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]
                    },
                    {
                        "handle": "ORG-123",
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Inc."], ["kind", {}, "text", "org"]]]
                    },
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "John Doe"], ["kind", {}, "text", "individual"]]]
                    }
                ],
                "nameservers": [
                    {"ldhName": "NS1.EXAMPLE.COM."},
                    {"ldhName": "ns1.example.com"}
                ],
                "status": ["clientTransferProhibited", "clientTransferProhibited"]
            }
        return m

    with patch('httpx.Client.get', side_effect=mock_get):
        res = collect_domain_rdap("example.com")
        assert res["status"] == "success"
        assert res["handle"] == "12345"
        assert res["registration_date"] == "1997-09-15T04:00:00Z"
        assert res["expiration_date"] == "2025-09-14T04:00:00Z"
        assert res["last_changed_date"] == "2023-01-01T00:00:00Z"
        assert res["registrar"]["name"] == "Example Registrar"
        assert res["registrar"]["handle"] == "REG-123"
        assert res["organization"]["name"] == "Example Inc."
        assert res["organization"]["handle"] == "ORG-123"
        assert res["nameservers"] == ["ns1.example.com"]
        assert res["domain_statuses"] == ["clientTransferProhibited"]

def test_rdap_statuses():
    def mock_get(url, **kwargs):
        m = MagicMock()
        if "data.iana.org" in str(url):
            m.status_code = 200
            m.json.return_value = {"services": [[["com"], ["https://rdap.com/"]]]}
            return m
        
        if "404" in str(url): m.status_code = 404
        elif "429" in str(url): m.status_code = 429
        elif "500" in str(url): m.status_code = 500
        elif "invalid" in str(url):
            m.status_code = 200
            m.json.side_effect = ValueError("Invalid JSON")
        return m

    with patch('httpx.Client.get', side_effect=mock_get):
        assert collect_domain_rdap("404.com")["status"] == "not_found"
        assert collect_domain_rdap("429.com")["status"] == "rate_limited"
        assert collect_domain_rdap("500.com")["status"] == "error"
        assert collect_domain_rdap("invalid.com")["status"] == "error"

def test_rdap_redirects():
    def mock_get(url, **kwargs):
        m = MagicMock()
        url = str(url)
        if "data.iana.org" in url:
            m.status_code = 200
            m.json.return_value = {"services": [[["com"], ["https://rdap.com/"]]]}
            return m
        
        if url == "https://rdap.com/domain/redir.com":
            m.status_code = 301
            m.headers = {"location": "https://rdap.com/domain/redir2.com"}
        elif url == "https://rdap.com/domain/redir2.com":
            m.status_code = 200
            m.json.return_value = {"handle": "DONE"}
        elif url == "https://rdap.com/domain/badredir.com":
            m.status_code = 301
            m.headers = {"location": "http://127.0.0.1/admin"}
        elif url == "https://rdap.com/domain/loop.com":
            m.status_code = 301
            m.headers = {"location": "https://rdap.com/domain/loop.com"}
        else:
            m.status_code = 404
        return m

    with patch('httpx.Client.get', side_effect=mock_get):
        res = collect_domain_rdap("redir.com")
        assert res["status"] == "success"
        
        res = collect_domain_rdap("badredir.com")
        assert res["status"] == "error"
        
        res = collect_domain_rdap("loop.com")
        assert res["status"] == "error"

def test_cache_behavior():
    call_count = 0
    def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {"services": [[["com"], ["https://rdap.com/"]]]}
        return m
        
    with patch('httpx.Client.get', side_effect=mock_get):
        _get_iana_bootstrap()
        assert call_count == 1
        
        _get_iana_bootstrap()
        assert call_count == 1  # Used cache
        
        rdap_module._IANA_BOOTSTRAP_TIMESTAMP -= 90000
        _get_iana_bootstrap()
        assert call_count == 2

