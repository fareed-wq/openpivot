from unittest.mock import patch, MagicMock
import pytest
import dns.resolver
import dns.exception
from app.intelligence.email_security import collect_email_security

@pytest.fixture
def mock_resolver_resolve():
    with patch('dns.resolver.Resolver.resolve') as mock_resolve:
        yield mock_resolve

def test_full_present(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = lambda q, t: [
        MagicMock(strings=[b"v=DMARC1; p=reject;"])
    ] if q.startswith("_dmarc") else []
    
    dns_data = {
        "records": {
            "MX": {
                "status": "success",
                "values": [{"priority": 10, "host": "aspmx.l.google.com"}]
            },
            "TXT": {
                "status": "success",
                "values": ["v=spf1 include:_spf.google.com ~all", "some other txt"]
            }
        }
    }
    
    result = collect_email_security("example.com", dns_data)
    assert result["status"] == "success"
    assert result["mx"]["status"] == "present"
    assert result["mx"]["records"][0]["provider"] == "Google"
    assert result["spf"]["status"] == "present"
    assert result["spf"]["record"] == "v=spf1 include:_spf.google.com ~all"
    assert result["dmarc"]["status"] == "present"
    assert result["dmarc"]["record"] == "v=DMARC1; p=reject;"

def test_absent_records(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = dns.resolver.NXDOMAIN()
    dns_data = {
        "records": {
            "MX": {"status": "nxdomain", "values": []},
            "TXT": {"status": "no_answer", "values": []}
        }
    }
    result = collect_email_security("example.com", dns_data)
    assert result["status"] == "success"
    assert result["mx"]["status"] == "absent"
    assert result["spf"]["status"] == "absent"
    assert result["dmarc"]["status"] == "absent"

def test_unknown_provider(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = dns.resolver.NoAnswer()
    dns_data = {
        "records": {
            "MX": {
                "status": "success",
                "values": [{"priority": 10, "host": "mail.unknown.com"}]
            },
            "TXT": {"status": "success", "values": ["just txt"]}
        }
    }
    result = collect_email_security("example.com", dns_data)
    assert result["mx"]["records"][0]["provider"] is None
    assert result["spf"]["status"] == "absent"

def test_dmarc_timeout_partial(mock_resolver_resolve):
    mock_resolver_resolve.side_effect = dns.exception.Timeout()
    dns_data = {
        "records": {
            "MX": {"status": "success", "values": [{"priority": 10, "host": "mail.unknown.com"}]},
            "TXT": {"status": "success", "values": ["v=spf1 -all"]}
        }
    }
    result = collect_email_security("example.com", dns_data)
    assert result["status"] == "partial"
    assert result["mx"]["status"] == "present"
    assert result["spf"]["status"] == "present"
    assert result["dmarc"]["status"] == "unavailable"

def test_full_failure():
    with patch('app.intelligence.email_security.collect_dns_intelligence') as mock_dns:
        mock_dns.return_value = {
            "records": {
                "MX": {"status": "timeout", "values": []},
                "TXT": {"status": "error", "values": []}
            }
        }
        with patch('dns.resolver.Resolver.resolve') as mock_dmarc:
            mock_dmarc.side_effect = dns.exception.Timeout()
            result = collect_email_security("example.com")
            
            assert result["status"] == "error"
            assert result["mx"]["status"] == "unavailable"
            assert result["spf"]["status"] == "unavailable"
            assert result["dmarc"]["status"] == "unavailable"
