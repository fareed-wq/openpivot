import pytest
from app.intelligence.correlation import build_correlations

def test_empty_correlation():
    res = build_correlations()
    assert res["entities"] == []
    assert res["relationships"] == []

def test_dns_correlation():
    dns_res = {
        "status": "success",
        "domain": "example.com",
        "records": {
            "A": {"status": "success", "values": ["93.184.216.34", "93.184.216.34"]},
            "AAAA": {"status": "success", "values": ["2606:2800:220:1:248:1893:25c8:1946"]},
            "NS": {"status": "success", "values": ["ns1.example.net.", "ns1.example.net"]},
            "MX": {"status": "success", "values": [{"priority": 10, "host": "mail.example.com"}]}
        }
    }
    
    res = build_correlations(dns_result=dns_res)
    
    ent_ids = [e["id"] for e in res["entities"]]
    assert "domain:example.com" in ent_ids
    assert "ip:93.184.216.34" in ent_ids
    assert "ip:2606:2800:220:1:248:1893:25c8:1946" in ent_ids
    assert "ns:ns1.example.net" in ent_ids
    assert "mx:mail.example.com" in ent_ids
    
    # Check lengths for deduplication
    assert len(res["entities"]) == 5
    assert len(res["relationships"]) == 4
    
    rel_ids = [f"{r['source']}|{r['type']}|{r['target']}" for r in res["relationships"]]
    assert "domain:example.com|resolves_to|ip:93.184.216.34" in rel_ids
    assert "domain:example.com|uses_nameserver|ns:ns1.example.net" in rel_ids

def test_tls_correlation():
    tls_res = {
        "status": "success",
        "domain": "example.com",
        "certificate": {
            "sha256_fingerprint": "AB:CD:EF:12:34:56",
            "subject": "CN=example.com",
            "issuer": "O=Test CA",
            "san_dns": ["example.com", "www.example.com"]
        }
    }
    
    res = build_correlations(tls_result=tls_res)
    
    ent_ids = [e["id"] for e in res["entities"]]
    assert "domain:example.com" in ent_ids
    assert "cert:abcdef123456" in ent_ids
    assert "host:example.com" in ent_ids
    assert "host:www.example.com" in ent_ids
    
    rel_ids = [f"{r['source']}|{r['type']}|{r['target']}" for r in res["relationships"]]
    assert "domain:example.com|presents_certificate|cert:abcdef123456" in rel_ids
    assert "cert:abcdef123456|contains_hostname|host:example.com" in rel_ids
    assert "cert:abcdef123456|contains_hostname|host:www.example.com" in rel_ids

def test_ip_and_asn_correlation():
    ip_res = {
        "ip": "8.8.8.8",
        "rdap": {
            "network_prefixes": ["8.8.8.0/24"],
            "country": "US",
            "name": "GOOGLE",
            "organization": {
                "name": "Google LLC",
                "handle": "GOGL"
            }
        },
        "reverse_dns": {
            "status": "success",
            "hostname": "dns.google"
        }
    }
    
    asn_res = {
        "origin": {
            "ip": "8.8.8.8",
            "asns": [15169],
            "prefix": "8.8.8.0/24",
            "country": "US"
        },
        "asn": {
            "number": 15169,
            "name": "GOOGLE",
            "organization": {
                "name": "Google LLC",
                "handle": "GOGL"
            }
        }
    }
    
    res = build_correlations(ip_result=ip_res, asn_result=asn_res)
    
    ent_ids = [e["id"] for e in res["entities"]]
    assert "ip:8.8.8.8" in ent_ids
    assert "host:dns.google" in ent_ids
    assert "asn:15169" in ent_ids
    assert "org:gogl" in ent_ids
    
    rel_ids = [f"{r['source']}|{r['type']}|{r['target']}" for r in res["relationships"]]
    assert "ip:8.8.8.8|reverse_resolves_to|host:dns.google" in rel_ids
    assert "ip:8.8.8.8|announced_by|asn:15169" in rel_ids
    assert "ip:8.8.8.8|registered_to|org:gogl" in rel_ids
    assert "asn:15169|registered_to|org:gogl" in rel_ids
    
    # Organization source_collectors should merge
    org_rel = next(r for r in res["relationships"] if r["source"] == "ip:8.8.8.8" and r["target"] == "org:gogl")
    assert "ip_rdap" in org_rel["source_collectors"]

def test_org_deduplication():
    # IP has name but no handle
    ip_res = {
        "ip": "1.1.1.1",
        "rdap": {
            "organization": {
                "name": "Cloudflare, Inc."
            }
        }
    }
    
    # ASN has name and handle
    asn_res = {
        "asn": {
            "number": 13335,
            "organization": {
                "name": "Cloudflare, Inc.  ", # test whitespace normalization
                "handle": "CF"
            }
        }
    }
    
    res = build_correlations(ip_result=ip_res, asn_result=asn_res)
    
    ent_ids = [e["id"] for e in res["entities"]]
    assert "org:cf" in ent_ids
    assert "org:name_cloudflare,_inc." not in ent_ids
    assert len([e for e in res["entities"] if e["type"] == "organization"]) == 1

def test_ordering():
    dns_res = {
        "status": "success",
        "domain": "b.com",
        "records": {
            "A": {"status": "success", "values": ["2.2.2.2", "1.1.1.1"]}
        }
    }
    res = build_correlations(dns_result=dns_res)
    
    ent_ids = [e["id"] for e in res["entities"]]
    # Domain first (d before i), then IP 1.1.1.1 before 2.2.2.2
    assert ent_ids == ["domain:b.com", "ip:1.1.1.1", "ip:2.2.2.2"]
    
    rel_ids = [f"{r['source']}|{r['type']}|{r['target']}" for r in res["relationships"]]
    assert rel_ids == [
        "domain:b.com|resolves_to|ip:1.1.1.1",
        "domain:b.com|resolves_to|ip:2.2.2.2"
    ]
