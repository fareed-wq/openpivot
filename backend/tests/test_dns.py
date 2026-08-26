from unittest.mock import patch, MagicMock
import pytest
from app.intelligence.dns import collect_dns_intelligence
import dns.resolver
import dns.exception

@pytest.fixture
def mock_resolver_resolve():
    with patch('dns.resolver.Resolver.resolve') as mock_resolve:
        yield mock_resolve

def test_successful_dns_normalization(mock_resolver_resolve):
    def mock_resolve_side_effect(domain, rtype):
        if rtype == "A":
            m = MagicMock()
            m.to_text.return_value = "93.184.216.34"
            return [m]
        elif rtype == "AAAA":
            m = MagicMock()
            m.to_text.return_value = "2606:2800:220:1:248:1893:25c8:1946"
            return [m]
        elif rtype == "NS":
            m = MagicMock()
            m.target.to_text.return_value = "ns1.example.com."
            return [m]
        elif rtype == "CNAME":
            m = MagicMock()
            m.target.to_text.return_value = "alias.example.com."
            return [m]
        elif rtype == "MX":
            m = MagicMock()
            m.preference = 10
            m.exchange.to_text.return_value = "mail.example.com."
            return [m]
        elif rtype == "TXT":
            m = MagicMock()
            m.strings = [b"v=spf1 ", b"include:_spf.example.com ~all"]
            return [m]
        elif rtype == "CAA":
            m = MagicMock()
            m.flags = 0
            m.tag = b"issue"
            m.value = b"letsencrypt.org"
            return [m]
        else:
            raise dns.resolver.NoAnswer()
            
    mock_resolver_resolve.side_effect = mock_resolve_side_effect
    
    result = collect_dns_intelligence("example.com")
    
    assert result["status"] == "success"
    assert result["records"]["A"]["values"] == ["93.184.216.34"]
    assert result["records"]["AAAA"]["values"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert result["records"]["NS"]["values"] == ["ns1.example.com"]
    assert result["records"]["CNAME"]["values"] == ["alias.example.com"]
    assert result["records"]["MX"]["values"] == [{"priority": 10, "host": "mail.example.com"}]
    assert result["records"]["TXT"]["values"] == ["v=spf1 include:_spf.example.com ~all"]
    assert result["records"]["CAA"]["values"] == [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]

def test_no_answer_does_not_crash(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = dns.resolver.NoAnswer()
    result = collect_dns_intelligence("example.com")
    assert result["status"] == "success"
    assert result["records"]["A"]["status"] == "no_answer"
    assert result["records"]["MX"]["status"] == "no_answer"

def test_timeout_partial_success(mock_resolver_resolve):
    def mock_resolve_side_effect(domain, rtype):
        if rtype == "A":
            m = MagicMock()
            m.to_text.return_value = "1.2.3.4"
            return [m]
        else:
            raise dns.exception.Timeout()
            
    mock_resolver_resolve.side_effect = mock_resolve_side_effect
    result = collect_dns_intelligence("example.com")
    
    assert result["status"] == "partial"
    assert result["records"]["A"]["status"] == "success"
    assert result["records"]["MX"]["status"] == "timeout"
    assert result["records"]["MX"]["error"] == "DNS query timed out"

def test_nxdomain_handling(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = dns.resolver.NXDOMAIN()
    result = collect_dns_intelligence("nonexistent.example")
    
    assert result["status"] == "error"
    assert result["records"]["A"]["status"] == "nxdomain"

def test_no_nameservers_handling(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = dns.resolver.NoNameservers()
    result = collect_dns_intelligence("example.com")
    
    assert result["status"] == "error"
    assert result["records"]["A"]["status"] == "error"
    assert result["records"]["A"]["error"] == "No nameservers found"
