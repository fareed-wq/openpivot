import time
import ipaddress
import httpx
import dns.resolver
import dns.reversename
import dns.exception
import re
from datetime import datetime, timezone
from typing import Optional, Tuple

from app.intelligence.rdap import _fetch_rdap, _is_safe_url, CONNECT_TIMEOUT, READ_TIMEOUT
from app.models.asn import ASNIntelligenceResult, ASNOrigin, ASNRDAPIntelligence, ASNEntity

IANA_ASN_BOOTSTRAP_URL = "https://data.iana.org/rdap/asn.json"
CACHE_TTL = 86400

_IANA_ASN_BOOTSTRAP_CACHE: list = []
_IANA_ASN_BOOTSTRAP_TIMESTAMP: float = 0.0

def normalize_asn(asn_input) -> Optional[int]:
    if asn_input is None:
        return None
    s = str(asn_input).strip().lower()
    if s.startswith('as'):
        s = s[2:]
    if not s.isdigit():
        return None
    val = int(s)
    
    # Validation against public ASN assignment rules
    if val <= 0:
        return None
    if val == 23456: # AS_TRANS
        return None
    if 64496 <= val <= 64511: # Documentation
        return None
    if 64512 <= val <= 65534: # Private Use
        return None
    if val == 65535: # Reserved
        return None
    if 65536 <= val <= 65551: # Documentation
        return None
    if 4200000000 <= val <= 4294967294: # Private Use
        return None
    if val >= 4294967295: # Reserved / Out of bounds
        return None
        
    return val

def _get_iana_asn_bootstrap() -> list:
    global _IANA_ASN_BOOTSTRAP_CACHE, _IANA_ASN_BOOTSTRAP_TIMESTAMP
    now = time.time()
    
    if _IANA_ASN_BOOTSTRAP_CACHE and (now - _IANA_ASN_BOOTSTRAP_TIMESTAMP) < CACHE_TTL:
        return _IANA_ASN_BOOTSTRAP_CACHE
        
    with httpx.Client(timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)) as client:
        try:
            resp = client.get(IANA_ASN_BOOTSTRAP_URL)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return _IANA_ASN_BOOTSTRAP_CACHE
            
        new_cache = []
        for ranges, urls in data.get("services", []):
            best_url = None
            for u in urls:
                if u.startswith("https://") and _is_safe_url(u):
                    best_url = u
                    break
            if not best_url:
                for u in urls:
                    if _is_safe_url(u):
                        best_url = u
                        break
            if best_url:
                for r in ranges:
                    parts = r.split('-')
                    if len(parts) == 1:
                        start = end = int(parts[0])
                    elif len(parts) == 2:
                        start, end = int(parts[0]), int(parts[1])
                    else:
                        continue
                    new_cache.append((start, end, best_url))
        
        _IANA_ASN_BOOTSTRAP_CACHE = new_cache
        _IANA_ASN_BOOTSTRAP_TIMESTAMP = now
        return _IANA_ASN_BOOTSTRAP_CACHE

def _get_team_cymru_origin(ip: str) -> dict:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            return {"status": "unsupported"}
    except ValueError:
        return {"status": "error"}
        
    reversed_ip = '.'.join(reversed(ip.split('.')))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        ans = resolver.resolve(query, "TXT")
        
        txt_record = str(ans[0]).strip('"\'')
        parts = [p.strip() for p in txt_record.split('|')]
        
        if len(parts) < 1:
            return {"status": "error"}
            
        asns_raw = parts[0].split()
        asns = []
        for a in asns_raw:
            val = normalize_asn(a)
            if val is not None and val not in asns:
                asns.append(val)
                
        if not asns:
            return {"status": "not_found"}
            
        prefix = None
        if len(parts) > 1:
            raw_prefix = parts[1]
            try:
                network = ipaddress.ip_network(raw_prefix, strict=False)
                if network.version == 4 and ip_obj in network:
                    prefix = raw_prefix
            except ValueError:
                pass
            
        return {
            "status": "success",
            "asns": asns,
            "prefix": prefix,
            "country": parts[2] if len(parts) > 2 else None,
            "registry": parts[3] if len(parts) > 3 else None,
            "allocated": parts[4] if len(parts) > 4 else None,
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {"status": "not_found"}
    except dns.exception.Timeout:
        return {"status": "timeout"}
    except Exception:
        return {"status": "error"}

def collect_asn_intelligence_from_ip(ip: str) -> dict:
    origin_res = _get_team_cymru_origin(ip)
    
    if origin_res["status"] != "success":
        return ASNIntelligenceResult(
            status=origin_res["status"],
            queried_at=datetime.now(timezone.utc).isoformat()
        ).model_dump()
        
    origin_obj = ASNOrigin(
        ip=ip,
        asns=origin_res["asns"],
        prefix=origin_res.get("prefix"),
        country=origin_res.get("country"),
        registry=origin_res.get("registry"),
        allocated=origin_res.get("allocated")
    )
    
    primary_asn = origin_res["asns"][0]
    
    bootstrap = _get_iana_asn_bootstrap()
    base_url = None
    if bootstrap:
        # Longest match logic - for ASN ranges, the narrowest range is the best match
        best_range_len = float('inf')
        for start, end, url in bootstrap:
            if start <= primary_asn <= end:
                range_len = end - start
                if range_len < best_range_len:
                    best_range_len = range_len
                    base_url = url
                    
    rdap_status = "success" if base_url else "unsupported"
    rdap_obj = None
    
    if base_url:
        if not base_url.endswith('/'):
            base_url += '/'
        rdap_url = f"{base_url}autnum/{primary_asn}"
        
        fetch_res = _fetch_rdap(rdap_url)
        rdap_status = fetch_res["status"]
        
        if rdap_status == "success":
            data = fetch_res["data"]
            rdap_obj = ASNRDAPIntelligence(source=fetch_res["source"])
            
            rdap_obj.number = primary_asn
            rdap_obj.handle = data.get("handle")
            rdap_obj.name = data.get("name")
            start_autnum = data.get("startAutnum")
            end_autnum = data.get("endAutnum")
            
            # If the range does not include the queried ASN, handle as inconsistent provider data
            if start_autnum is not None and end_autnum is not None:
                if not (start_autnum <= primary_asn <= end_autnum):
                    return ASNIntelligenceResult(
                        status="partial",
                        queried_at=datetime.now(timezone.utc).isoformat(),
                        origin=origin_obj,
                        asn=None
                    ).model_dump()
            
            rdap_obj.start_autnum = start_autnum
            rdap_obj.end_autnum = end_autnum
            rdap_obj.country = data.get("country")
            rdap_obj.type = data.get("type")
            
            statuses = data.get("status", [])
            rdap_obj.statuses = list(set(statuses))
            
            for ev in data.get("events", []):
                action = ev.get("eventAction", "").lower()
                dt = ev.get("eventDate")
                if action == "registration":
                    rdap_obj.registration_date = dt
                elif action in ("last changed", "last update of rdap database"):
                    rdap_obj.last_changed_date = dt
                    
            for ent in data.get("entities", []):
                vcard = ent.get("vcardArray", [])
                
                ent_name = None
                ent_kind = None
                if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if isinstance(prop, list) and len(prop) >= 4:
                            if prop[0] == "fn":
                                ent_name = str(prop[3])
                            elif prop[0] == "kind":
                                ent_kind = str(prop[3])
                
                if ent_kind and ent_kind.lower() == "org" and ent_name:
                    rdap_obj.organization = ASNEntity(name=ent_name, handle=ent.get("handle"))
                    break
                    
    # Isolation
    overall_status = "partial" if rdap_status != "success" else "success"
    
    return ASNIntelligenceResult(
        status=overall_status,
        queried_at=datetime.now(timezone.utc).isoformat(),
        origin=origin_obj,
        asn=rdap_obj
    ).model_dump()
