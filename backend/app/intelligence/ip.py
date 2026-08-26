import time
import ipaddress
import httpx
import dns.resolver
import dns.reversename
import dns.exception
from datetime import datetime, timezone
from typing import Optional

from app.intelligence.rdap import _fetch_rdap, _is_safe_url, CONNECT_TIMEOUT, READ_TIMEOUT
from app.models.ip import IPIntelligenceResult, IPRDAPIntelligence, IPReverseDNS, IPEntity

IANA_IPV4_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
CACHE_TTL = 86400

_IANA_IPV4_BOOTSTRAP_CACHE: list = []
_IANA_IPV4_BOOTSTRAP_TIMESTAMP: float = 0.0

def _get_iana_ipv4_bootstrap() -> list:
    global _IANA_IPV4_BOOTSTRAP_CACHE, _IANA_IPV4_BOOTSTRAP_TIMESTAMP
    now = time.time()
    
    if _IANA_IPV4_BOOTSTRAP_CACHE and (now - _IANA_IPV4_BOOTSTRAP_TIMESTAMP) < CACHE_TTL:
        return _IANA_IPV4_BOOTSTRAP_CACHE
        
    with httpx.Client(timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)) as client:
        try:
            resp = client.get(IANA_IPV4_BOOTSTRAP_URL)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return _IANA_IPV4_BOOTSTRAP_CACHE
        
        new_cache = []
        for prefixes, urls in data.get("services", []):
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
                for prefix in prefixes:
                    try:
                        network = ipaddress.ip_network(prefix)
                        new_cache.append((network, best_url))
                    except ValueError:
                        pass
                        
        _IANA_IPV4_BOOTSTRAP_CACHE = new_cache
        _IANA_IPV4_BOOTSTRAP_TIMESTAMP = now
        return _IANA_IPV4_BOOTSTRAP_CACHE

def _get_reverse_dns(ip: str) -> dict:
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        ans = resolver.resolve(rev_name, "PTR")
        hostname = str(ans[0]).lower()
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        return {"status": "success", "hostname": hostname}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {"status": "no_answer"}
    except dns.exception.Timeout:
        return {"status": "timeout"}
    except Exception:
        return {"status": "error"}

def collect_ip_intelligence(ip: str) -> dict:
    try:
        target_ip = ipaddress.ip_address(ip)
        if target_ip.version != 4:
            return IPIntelligenceResult(ip=ip, status="blocked", queried_at=datetime.now(timezone.utc).isoformat()).model_dump()
        if target_ip.is_private or target_ip.is_loopback or target_ip.is_multicast or target_ip.is_unspecified or target_ip.is_link_local or target_ip.is_reserved:
            return IPIntelligenceResult(ip=ip, status="blocked", queried_at=datetime.now(timezone.utc).isoformat()).model_dump()
    except ValueError:
        return IPIntelligenceResult(ip=ip, status="error", queried_at=datetime.now(timezone.utc).isoformat()).model_dump()
        
    bootstrap = _get_iana_ipv4_bootstrap()
    if not bootstrap:
        # Just fail rdap and try PTR
        base_url = None
        rdap_status = "error"
    else:
        best_network = None
        for network, url in bootstrap:
            if target_ip in network:
                if best_network is None or network.prefixlen > best_network.prefixlen:
                    best_network = network
                    base_url = url
        rdap_status = "success" if base_url else "unsupported"
        
    rdap_res = None
    if base_url:
        if not base_url.endswith('/'):
            base_url += '/'
        rdap_url = f"{base_url}ip/{ip}"
        fetch_res = _fetch_rdap(rdap_url)
        rdap_status = fetch_res["status"]
        
        if rdap_status == "success":
            data = fetch_res["data"]
            rdap_res = IPRDAPIntelligence(source=fetch_res["source"])
            
            rdap_res.handle = data.get("handle")
            rdap_res.name = data.get("name")
            rdap_res.start_address = data.get("startAddress")
            rdap_res.end_address = data.get("endAddress")
            rdap_res.ip_version = data.get("ipVersion")
            rdap_res.type = data.get("type")
            rdap_res.country = data.get("country")
            rdap_res.parent_handle = data.get("parentHandle")
            
            statuses = data.get("status", [])
            rdap_res.statuses = list(set(statuses))
            
            for ev in data.get("events", []):
                action = ev.get("eventAction", "").lower()
                dt = ev.get("eventDate")
                if action == "registration":
                    rdap_res.registration_date = dt
                elif action in ("last changed", "last update of rdap database"):
                    rdap_res.last_changed_date = dt
                    
            prefixes = []
            for cidr in data.get("cidr0_cidrs", []):
                v4_prefix = cidr.get("v4prefix")
                length = cidr.get("length")
                if v4_prefix and length:
                    prefixes.append(f"{v4_prefix}/{length}")
                    
            if not prefixes and rdap_res.start_address and rdap_res.end_address:
                try:
                    start = ipaddress.ip_address(rdap_res.start_address)
                    end = ipaddress.ip_address(rdap_res.end_address)
                    if start.version == 4 and end.version == 4:
                        for subnet in ipaddress.summarize_address_range(start, end):
                            prefixes.append(str(subnet))
                except ValueError:
                    pass
                    
            rdap_res.network_prefixes = list(dict.fromkeys(prefixes))
            
            for ent in data.get("entities", []):
                roles = [r.lower() for r in ent.get("roles", [])]
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
                    rdap_res.organization = IPEntity(name=ent_name, handle=ent.get("handle"))
                    break # Take first org

    ptr_fetch = _get_reverse_dns(ip)
    ptr_res = IPReverseDNS(status=ptr_fetch["status"], hostname=ptr_fetch.get("hostname"))
    
    # Determine overall status
    if rdap_status == "success" and ptr_res.status in ("success", "no_answer"):
        overall_status = "success"
    elif rdap_status == "success" and ptr_res.status not in ("success", "no_answer"):
        overall_status = "partial"
    elif rdap_status != "success" and ptr_res.status in ("success", "no_answer"):
        overall_status = "partial"
    else:
        # Both failed or errored
        overall_status = rdap_status
        
    result = IPIntelligenceResult(
        ip=ip,
        status=overall_status,
        queried_at=datetime.now(timezone.utc).isoformat(),
        rdap=rdap_res,
        reverse_dns=ptr_res
    )
    
    return result.model_dump()
