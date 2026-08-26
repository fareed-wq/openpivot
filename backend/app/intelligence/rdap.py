import httpx
import time
import urllib.parse
import ipaddress
from typing import Optional, Dict
from datetime import datetime, timezone
from app.models.rdap import RDAPIntelligenceResult, RDAPEntity

CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
MAX_REDIRECTS = 3
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CACHE_TTL = 86400  # 24 hours

_IANA_BOOTSTRAP_CACHE: Dict[str, str] = {}
_IANA_BOOTSTRAP_TIMESTAMP: float = 0.0

def _is_safe_url(url_str: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower()
        if hostname in ("localhost", "localhost.localdomain"):
            return False
        
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                return False
        except ValueError:
            pass 
        
        return True
    except Exception:
        return False

def _get_iana_bootstrap() -> Dict[str, str]:
    global _IANA_BOOTSTRAP_CACHE, _IANA_BOOTSTRAP_TIMESTAMP
    now = time.time()
    
    if _IANA_BOOTSTRAP_CACHE and (now - _IANA_BOOTSTRAP_TIMESTAMP) < CACHE_TTL:
        return _IANA_BOOTSTRAP_CACHE
        
    with httpx.Client(timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)) as client:
        try:
            resp = client.get(IANA_BOOTSTRAP_URL)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return _IANA_BOOTSTRAP_CACHE
        
        new_cache = {}
        for tlds, urls in data.get("services", []):
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
                for tld in tlds:
                    new_cache[tld.lower()] = best_url
                    
        _IANA_BOOTSTRAP_CACHE = new_cache
        _IANA_BOOTSTRAP_TIMESTAMP = now
        return _IANA_BOOTSTRAP_CACHE

def _fetch_rdap(url: str) -> dict:
    current_url = url
    redirects = 0
    with httpx.Client(timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)) as client:
        while redirects <= MAX_REDIRECTS:
            if not _is_safe_url(current_url):
                return {"status": "error"}
            
            try:
                resp = client.get(current_url, follow_redirects=False)
            except httpx.TimeoutException:
                return {"status": "timeout"}
            except httpx.RequestError:
                return {"status": "error"}
            
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return {"status": "error"}
                current_url = urllib.parse.urljoin(current_url, location)
                redirects += 1
                continue
            
            if resp.status_code == 200:
                try:
                    return {"status": "success", "data": resp.json(), "source": current_url}
                except ValueError:
                    return {"status": "error"}
            elif resp.status_code == 404:
                return {"status": "not_found"}
            elif resp.status_code == 429:
                return {"status": "rate_limited"}
            elif resp.status_code >= 500:
                return {"status": "error"}
            else:
                return {"status": "error"}
                
        return {"status": "error"}

def collect_domain_rdap(domain: str) -> dict:
    tld = domain.strip().split('.')[-1].lower()
    bootstrap = _get_iana_bootstrap()
    
    if not bootstrap:
        return RDAPIntelligenceResult(
            domain=domain,
            status="error",
            queried_at=datetime.now(timezone.utc).isoformat()
        ).model_dump()
        
    base_url = bootstrap.get(tld)
    if not base_url:
        return RDAPIntelligenceResult(
            domain=domain,
            status="unsupported",
            queried_at=datetime.now(timezone.utc).isoformat()
        ).model_dump()
        
    if not base_url.endswith('/'):
        base_url += '/'
    rdap_url = f"{base_url}domain/{domain}"
    
    resp = _fetch_rdap(rdap_url)
    
    result = RDAPIntelligenceResult(
        domain=domain,
        status=resp["status"],
        queried_at=datetime.now(timezone.utc).isoformat()
    )
    
    if resp["status"] != "success":
        return result.model_dump()
        
    result.source = resp["source"]
    data = resp["data"]
    
    result.handle = data.get("handle")
    
    # Dates
    for ev in data.get("events", []):
        action = ev.get("eventAction", "").lower()
        dt = ev.get("eventDate")
        if action == "registration":
            result.registration_date = dt
        elif action == "expiration":
            result.expiration_date = dt
        elif action in ("last changed", "last update of rdap database"):
            result.last_changed_date = dt
            
    # Entities (registrar / org)
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
        
        if "registrar" in roles and not result.registrar:
            result.registrar = RDAPEntity(name=ent_name, handle=ent.get("handle"))
            
        if "registrant" in roles and not result.organization:
            if ent_kind and ent_kind.lower() == "org" and ent_name:
                result.organization = RDAPEntity(name=ent_name, handle=ent.get("handle"))
                
    # Nameservers
    ns_list = []
    for ns in data.get("nameservers", []):
        ldh = ns.get("ldhName")
        if ldh:
            ldh = ldh.lower()
            if ldh.endswith('.'):
                ldh = ldh[:-1]
            if ldh not in ns_list:
                ns_list.append(ldh)
    result.nameservers = ns_list
    
    # Statuses
    statuses = data.get("status", [])
    result.domain_statuses = list(set(statuses))
    
    return result.model_dump()
