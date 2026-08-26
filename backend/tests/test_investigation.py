import pytest
from fastapi.testclient import TestClient
from app.main import app
from unittest.mock import patch, MagicMock
from app.intelligence.investigation import run_investigation

client = TestClient(app)

@patch("app.intelligence.investigation.collect_dns_intelligence")
@patch("app.intelligence.investigation.collect_email_security")
@patch("app.intelligence.investigation.collect_domain_rdap")
@patch("app.intelligence.investigation.collect_tls_intelligence")
@patch("app.intelligence.investigation.collect_http_metadata")
@patch("app.intelligence.investigation.collect_ip_intelligence")
@patch("app.intelligence.investigation.collect_asn_intelligence_from_ip")
def test_domain_investigation_routing(mock_asn, mock_ip, mock_http, mock_tls, mock_rdap, mock_email, mock_dns):
    mock_dns.return_value = {"status": "success", "domain": "example.com", "records": {}}
    mock_email.return_value = {"status": "success"}
    mock_rdap.return_value = {"status": "success"}
    mock_tls.return_value = {"status": "success"}
    mock_http.return_value = {"status": "success"}
    
    response = client.post("/investigate", json={"target": "example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["target"]["normalized"] == "example.com"
    assert "investigation_id" in data
    assert "started_at" in data
    assert "completed_at" in data
    assert data["duration_ms"] >= 0
    
    # Verify collectors called
    mock_dns.assert_called_once()
    mock_email.assert_called_once()
    mock_rdap.assert_called_once()
    mock_tls.assert_called_once()
    mock_http.assert_called_once()
    
    # Verify IP/ASN NOT called
    mock_ip.assert_not_called()
    mock_asn.assert_not_called()
    
    # Verify keys
    assert "dns" in data["collectors"]
    assert "email_security" in data["collectors"]
    assert "ip" not in data["collectors"]

@patch("app.intelligence.investigation.collect_dns_intelligence")
@patch("app.intelligence.investigation.collect_email_security")
@patch("app.intelligence.investigation.collect_domain_rdap")
@patch("app.intelligence.investigation.collect_tls_intelligence")
@patch("app.intelligence.investigation.collect_http_metadata")
@patch("app.intelligence.investigation.collect_ip_intelligence")
@patch("app.intelligence.investigation.collect_asn_intelligence_from_ip")
def test_ipv4_investigation_routing(mock_asn, mock_ip, mock_http, mock_tls, mock_rdap, mock_email, mock_dns):
    mock_ip.return_value = {"status": "success", "ip": "8.8.8.8"}
    mock_asn.return_value = {"status": "success"}
    
    response = client.post("/investigate", json={"target": "8.8.8.8"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["target"]["normalized"] == "8.8.8.8"
    assert data["target"]["type"] == "ipv4"
    
    # Verify IP/ASN called
    mock_ip.assert_called_once_with("8.8.8.8")
    mock_asn.assert_called_once_with("8.8.8.8")
    
    # Verify domain NOT called
    mock_dns.assert_not_called()
    mock_email.assert_not_called()
    mock_rdap.assert_not_called()
    mock_tls.assert_not_called()
    mock_http.assert_not_called()

@patch("app.intelligence.investigation.collect_dns_intelligence")
@patch("app.intelligence.investigation.collect_email_security")
@patch("app.intelligence.investigation.collect_domain_rdap")
@patch("app.intelligence.investigation.collect_tls_intelligence")
@patch("app.intelligence.investigation.collect_http_metadata")
def test_domain_investigation_partial(mock_http, mock_tls, mock_rdap, mock_email, mock_dns):
    mock_dns.return_value = {"status": "success"}
    mock_email.return_value = {"status": "success"}
    mock_rdap.return_value = {"status": "success"}
    mock_tls.side_effect = Exception("Crash")
    mock_http.return_value = {"status": "timeout"}
    
    response = client.post("/investigate", json={"target": "example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["collector_status"]["tls"] == "error"
    assert data["collector_status"]["http_metadata"] == "timeout"
    assert data["collectors"]["tls"]["error"] == "Collector failed unexpectedly."

@patch("app.intelligence.investigation.collect_ip_intelligence")
@patch("app.intelligence.investigation.collect_asn_intelligence_from_ip")
def test_investigation_error_status(mock_asn, mock_ip):
    mock_ip.return_value = {"status": "error"}
    mock_asn.return_value = {"status": "timeout"}
    
    response = client.post("/investigate", json={"target": "8.8.8.8"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "error"

def test_investigate_api_invalid():
    response = client.post("/investigate", json={"target": "localhost"})
    assert response.status_code == 422
    
    response = client.post("/investigate", json={"target": "192.168.1.1"})
    assert response.status_code == 422
    
    response = client.post("/investigate", json={"target": "http://example.com"})
    assert response.status_code == 422

@patch("app.intelligence.investigation.collect_dns_intelligence")
@patch("app.intelligence.investigation.collect_email_security")
@patch("app.intelligence.investigation.collect_domain_rdap")
@patch("app.intelligence.investigation.collect_tls_intelligence")
@patch("app.intelligence.investigation.collect_http_metadata")
@patch("app.intelligence.investigation.build_correlations")
def test_correlation_exception(mock_corr, mock_http, mock_tls, mock_rdap, mock_email, mock_dns):
    mock_dns.return_value = {"status": "success", "domain": "example.com", "records": {}}
    mock_email.return_value = {"status": "success"}
    mock_rdap.return_value = {"status": "success"}
    mock_tls.return_value = {"status": "success"}
    mock_http.return_value = {"status": "success"}
    mock_corr.side_effect = Exception("Correlation crashed")
    
    response = client.post("/investigate", json={"target": "example.com"})
    assert response.status_code == 200
    data = response.json()
    
    # Should be partial since correlation crashed
    assert data["status"] == "partial"
    assert data["correlation"]["entities"] == []
    assert data["correlation"]["relationships"] == []
