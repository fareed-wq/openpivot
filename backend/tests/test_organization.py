import pytest
from app.intelligence.organization import derive_organization_footprint

class TestOrganizationFootprint:
    def test_empty(self):
        res = derive_organization_footprint({}, {})
        assert res["counts"]["organizations"] == 0

    def test_domain_rdap_org(self):
        collectors = {
            "rdap": {
                "status": "success",
                "organization": {"name": "Test Org LLC"},
                "nameservers": ["NS1.EXAMPLE.COM."]
            }
        }
        res = derive_organization_footprint(collectors, {})
        assert len(res["organizations"]) == 1
        assert res["organizations"][0]["name"] == "Test Org LLC"
        assert "Domain RDAP" in res["organizations"][0]["sources"]
        assert len(res["nameservers"]) == 1
        assert res["nameservers"][0] == "ns1.example.com"

    def test_ip_rdap_and_asn(self):
        collectors = {
            "ip": {
                "status": "success",
                "rdap": {
                    "organization": {"name": "Cloud Host Inc"},
                    "country": "US",
                    "network_prefixes": ["192.168.1.0/24"]
                }
            },
            "asn": {
                "status": "success",
                "asn": {
                    "number": 12345,
                    "organization": {"name": "Cloud Host Inc"},
                    "country": "US"
                },
                "origin": {
                    "ip": "192.168.1.5",
                    "asns": [12345, 67890]
                }
            }
        }
        res = derive_organization_footprint(collectors, {})
        assert len(res["organizations"]) == 1
        assert res["organizations"][0]["name"] == "Cloud Host Inc"
        assert "IP RDAP" in res["organizations"][0]["sources"]
        assert "ASN Registration" in res["organizations"][0]["sources"]
        
        assert "192.168.1.0/24" in res["prefixes"]
        assert "12345" in res["asns"]
        assert "67890" in res["asns"]
        assert "192.168.1.5" in res["ips"]

    def test_dns_and_http(self):
        collectors = {
            "dns": {
                "status": "success",
                "records": {
                    "A": {"status": "success", "values": ["1.1.1.1"]},
                    "MX": {"status": "success", "values": ["10 mail.example.com."]}
                }
            },
            "http_metadata": {
                "status": "success",
                "peer_ip": "1.1.1.1",
                "web_footprint": {
                    "technologies": [{"name": "Nginx", "category": "Web Server"}]
                }
            }
        }
        res = derive_organization_footprint(collectors, {})
        assert "1.1.1.1" in res["ips"]
        assert "mail.example.com" in res["mail_hosts"]
        assert len(res["technologies"]) == 1
        assert res["technologies"][0]["name"] == "Nginx"

    def test_correlation_fallback(self):
        correlation = {
            "entities": [
                {"type": "organization", "value": "Fallback Org", "id": "org:1"},
                {"type": "asn", "value": "999", "id": "asn:999"}
            ]
        }
        res = derive_organization_footprint({}, correlation)
        assert len(res["organizations"]) == 1
        assert res["organizations"][0]["name"] == "Fallback Org"
        assert "999" in res["asns"]
