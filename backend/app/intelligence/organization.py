from typing import Dict, Any

def derive_organization_footprint(collectors: Dict[str, Any], correlation: Dict[str, Any] = None) -> Dict[str, Any]:
    footprint = {
        "organizations": [],
        "asns": [],
        "ips": [],
        "prefixes": [],
        "nameservers": [],
        "mail_hosts": [],
        "technologies": [],
        "counts": {}
    }

    def add_org(name: str, source: str, context: str = None):
        if not name:
            return
        
        name_clean = name.strip()
        if not name_clean:
            return

        for o in footprint["organizations"]:
            if o["name"].lower() == name_clean.lower():
                if source not in o["sources"]:
                    o["sources"].append(source)
                if context and not o.get("context"):
                    o["context"] = context
                return
        
        footprint["organizations"].append({
            "name": name_clean,
            "sources": [source],
            "context": context
        })

    # 1. Domain RDAP
    domain_rdap = collectors.get("rdap")
    if domain_rdap and domain_rdap.get("status") == "success":
        org = domain_rdap.get("organization")
        if org and org.get("name"):
            add_org(org["name"], "Domain RDAP")
        for ns in domain_rdap.get("nameservers", []):
            ns_clean = ns.lower().rstrip('.')
            if ns_clean and ns_clean not in footprint["nameservers"]:
                footprint["nameservers"].append(ns_clean)

    # 2. IP RDAP
    ip_data = collectors.get("ip")
    if ip_data and ip_data.get("status") == "success":
        rdap = ip_data.get("rdap")
        if rdap:
            org = rdap.get("organization")
            if org and org.get("name"):
                add_org(org["name"], "IP RDAP", rdap.get("country"))
            
            for p in rdap.get("network_prefixes", []):
                if p not in footprint["prefixes"]:
                    footprint["prefixes"].append(p)

    # 3. ASN
    asn_data = collectors.get("asn")
    if asn_data and asn_data.get("status") == "success":
        asn_rdap = asn_data.get("asn")
        if asn_rdap:
            org = asn_rdap.get("organization")
            if org and org.get("name"):
                add_org(org["name"], "ASN Registration", asn_rdap.get("country"))
            
            num = asn_rdap.get("number")
            if num:
                n_str = str(num)
                if n_str not in footprint["asns"]:
                    footprint["asns"].append(n_str)
            
        origin = asn_data.get("origin")
        if origin and origin.get("ip"):
            if origin["ip"] not in footprint["ips"]:
                footprint["ips"].append(origin["ip"])
            for a in origin.get("asns", []):
                a_str = str(a)
                if a_str not in footprint["asns"]:
                    footprint["asns"].append(a_str)

    # 4. DNS
    dns_data = collectors.get("dns")
    if dns_data and dns_data.get("status") == "success":
        recs = dns_data.get("records", {})
        for t in ["A", "AAAA"]:
            if recs.get(t) and recs[t].get("status") == "success":
                for v in recs[t].get("values", []):
                    if v not in footprint["ips"]:
                        footprint["ips"].append(v)
        
        if recs.get("NS") and recs["NS"].get("status") == "success":
            for v in recs["NS"].get("values", []):
                v_clean = v.lower().rstrip('.')
                if v_clean not in footprint["nameservers"]:
                    footprint["nameservers"].append(v_clean)
        
        if recs.get("MX") and recs["MX"].get("status") == "success":
            for v in recs["MX"].get("values", []):
                parts = v.split()
                host = parts[-1].lower().rstrip('.')
                if host not in footprint["mail_hosts"]:
                    footprint["mail_hosts"].append(host)

    # 5. Web Footprint
    http_data = collectors.get("http_metadata")
    if http_data and http_data.get("status") in ["success", "partial"]:
        wf = http_data.get("web_footprint")
        if wf and wf.get("technologies"):
            for t in wf["technologies"]:
                if not any(x["name"] == t["name"] for x in footprint["technologies"]):
                    footprint["technologies"].append(t)
        
        peer_ip = http_data.get("peer_ip")
        if peer_ip and peer_ip not in footprint["ips"]:
            footprint["ips"].append(peer_ip)

    # 6. Correlation
    if correlation and correlation.get("entities"):
        for e in correlation["entities"]:
            t = e.get("type")
            v = e.get("value")
            if not v:
                continue
            
            if t == "asn" and v not in footprint["asns"]:
                footprint["asns"].append(v)
            elif t == "ip" and v not in footprint["ips"]:
                footprint["ips"].append(v)
            elif t == "organization":
                add_org(v, "Correlation Engine")
                
    if correlation and correlation.get("relationships"):
        for r in correlation["relationships"]:
            if r["type"] == "uses_nameserver":
                ns = r["target"].replace("host:", "")
                if ns not in footprint["nameservers"]:
                    footprint["nameservers"].append(ns)
            elif r["type"] == "uses_mail_host":
                mx = r["target"].replace("host:", "")
                if mx not in footprint["mail_hosts"]:
                    footprint["mail_hosts"].append(mx)

    # Sort
    footprint["asns"].sort()
    footprint["ips"].sort()
    footprint["prefixes"].sort()
    footprint["nameservers"].sort()
    footprint["mail_hosts"].sort()

    footprint["counts"] = {
        "organizations": len(footprint["organizations"]),
        "asns": len(footprint["asns"]),
        "ips": len(footprint["ips"]),
        "prefixes": len(footprint["prefixes"]),
        "nameservers": len(footprint["nameservers"]),
        "mail_hosts": len(footprint["mail_hosts"]),
        "technologies": len(footprint["technologies"])
    }

    return footprint
