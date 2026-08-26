import socket
import ssl
import http.client
import urllib.parse
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple, List

from app.core.network_safety import resolve_safe_addresses, NetworkSafetyError
from app.models.http_metadata import HTTPMetadataResult, HTTPSContext, RedirectRecord

CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 5.0
MAX_BODY_BYTES = 262144
MAX_REDIRECTS = 3

ALLOWED_HEADERS = {
    "server",
    "content-type",
    "content-length",
    "content-language",
    "via",
    "x-powered-by"
}

class SafeHTTPConnection(http.client.HTTPConnection):
    def __init__(self, ip: str, domain: str, *args, **kwargs):
        self._safe_ip = ip
        self._domain = domain
        super().__init__(ip, *args, **kwargs)
        
    def connect(self):
        self.sock = socket.create_connection((self._safe_ip, self.port), self.timeout)

class SafeHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, ip: str, domain: str, *args, **kwargs):
        self._safe_ip = ip
        self._domain = domain
        super().__init__(ip, *args, **kwargs)
        
    def connect(self):
        sock = socket.create_connection((self._safe_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._domain)

def _extract_title(html_bytes: bytes) -> Optional[str]:
    try:
        html_str = html_bytes.decode('utf-8', errors='ignore')
        match = re.search(r'<title[^>]*>(.*?)</title>', html_str, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1)
            title = re.sub(r'\s+', ' ', title).strip()
            return title[:512] if title else None
    except Exception:
        pass
    return None

def _is_safe_redirect_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.username or parsed.password:
            return False
        # Do not allow non-default/custom ports
        if parsed.port is not None and parsed.port not in (80, 443):
            return False
        # Reject control characters
        if any(ord(c) < 32 for c in url):
            return False
        return True
    except Exception:
        return False

def _fetch_url(url: str, method: str = "GET") -> Tuple[Optional[http.client.HTTPResponse], Optional[str], Optional[str], Optional[str]]:
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return None, None, None, "invalid url"
        
    scheme = parsed.scheme
    if scheme not in ("http", "https"):
        return None, None, None, "unsupported scheme"
        
    port = 443 if scheme == "https" else 80
    
    try:
        ips = resolve_safe_addresses(hostname)
    except NetworkSafetyError as e:
        if "DNS resolution failed" in str(e):
            return None, None, None, "dns failure"
        return None, None, None, "blocked"

    last_err = "unavailable"
    for ip in ips:
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                conn = SafeHTTPSConnection(ip, hostname, timeout=CONNECT_TIMEOUT, context=ctx)
            else:
                conn = SafeHTTPConnection(ip, hostname, timeout=CONNECT_TIMEOUT)
                
            path = parsed.path if parsed.path else "/"
            # Ensure fragment is NOT included
            if parsed.query:
                path += "?" + parsed.query
                
            headers = {
                "Host": hostname,
                "User-Agent": "OpenPivot/0.1",
                "Connection": "close"
            }
            conn.request(method, path, headers=headers)
            
            # Use sock.settimeout to enforce read timeout if available
            if getattr(conn, 'sock', None):
                conn.sock.settimeout(READ_TIMEOUT)
            resp = conn.getresponse()
            return resp, ip, None, None
        except ssl.SSLCertVerificationError:
            return None, None, "ssl_verify_failed", None
        except ssl.SSLError:
            last_err = "ssl_error"
        except socket.timeout:
            last_err = "timeout"
        except ConnectionRefusedError:
            last_err = "unavailable"
        except OSError:
            last_err = "unavailable"
        except Exception as e:
            print("ERROR IN FETCH:", str(e))
            last_err = "error"
            
    return None, None, None, last_err

def collect_http_metadata(domain: str) -> dict:
    result = HTTPMetadataResult(
        domain=domain,
        status="error",
        queried_at=datetime.now(timezone.utc).isoformat()
    )
    
    initial_url = f"https://{domain}/"
    result.initial_url = initial_url
    
    current_url = initial_url
    redirects_list = []
    
    https_reachable = False
    https_verified = False
    
    # Check HTTPS first
    resp, peer_ip, ssl_err, net_err = _fetch_url(current_url)
    if ssl_err == "ssl_verify_failed":
        https_reachable = True
        https_verified = False
        # Fallback to HTTP
        current_url = f"http://{domain}/"
        result.initial_url = current_url
        resp, peer_ip, ssl_err, net_err = _fetch_url(current_url)
    elif resp is not None:
        https_reachable = True
        https_verified = True
    else:
        https_reachable = False
        https_verified = False
        if net_err == "blocked":
            result.status = "blocked"
            return result.model_dump(by_alias=True)
        # Fallback to HTTP
        current_url = f"http://{domain}/"
        result.initial_url = current_url
        resp, peer_ip, ssl_err, net_err = _fetch_url(current_url)
        
    result.https = HTTPSContext(reachable=https_reachable, verified=https_verified)
    
    redirect_count = 0
    while redirect_count < MAX_REDIRECTS:
        if resp is None:
            if net_err == "blocked":
                result.status = "blocked"
            elif net_err == "timeout":
                result.status = "timeout"
            elif net_err == "unavailable":
                result.status = "unavailable"
            elif net_err == "dns failure":
                result.status = "unavailable"
            else:
                result.status = "error"
            
            # If we had successful prior hops but the redirect failed, it's a partial success
            if redirect_count > 0:
                result.status = "partial"
                
            result.redirects = redirects_list
            return result.model_dump(by_alias=True)
            
        status_code = resp.status
        if status_code in (301, 302, 303, 307, 308):
            loc = resp.getheader("Location")
            if not loc:
                break
            
            loc = urllib.parse.urljoin(current_url, loc)
            if not _is_safe_redirect_url(loc):
                result.status = "partial" if redirect_count > 0 else "blocked"
                result.redirects = redirects_list
                return result.model_dump(by_alias=True)
                
            redirects_list.append(RedirectRecord(**{
                "status_code": status_code,
                "from": current_url,
                "to": loc
            }))
            
            current_url = loc
            redirect_count += 1
            # Close previous connection
            resp.close()
            resp, peer_ip, ssl_err, net_err = _fetch_url(current_url)
        else:
            break
            
    if resp is None:
        # Loop ended but last fetch failed
        if redirect_count > 0:
            result.status = "partial"
        else:
            result.status = "error"
        result.redirects = redirects_list
        return result.model_dump(by_alias=True)
        
    # We have a final response
    if redirect_count >= MAX_REDIRECTS and resp.status in (301, 302, 303, 307, 308):
        result.status = "partial" # Hit redirect limit
    else:
        result.status = "success"
        
    result.final_url = current_url
    
    parsed = urllib.parse.urlparse(current_url)
    result.scheme = parsed.scheme
    result.hostname = parsed.hostname
    result.peer_ip = peer_ip
    result.status_code = resp.status
    result.redirects = redirects_list
    
    headers_dict = {}
    for k, v in resp.getheaders():
        k_lower = k.lower()
        if k_lower in ALLOWED_HEADERS:
            # Bound header values to 1024 characters
            headers_dict[k_lower] = v[:1024]
    result.headers = headers_dict
    
    # Read body for title
    content_type = headers_dict.get("content-type", "").lower()
    if "text/html" in content_type:
        try:
            body = resp.read(MAX_BODY_BYTES)
            title = _extract_title(body)
            if title:
                result.title = title
        except socket.timeout:
            result.status = "partial"
        except Exception:
            pass
            
    resp.close()
    
    # Force partial status if HTTPS fallback occurred
    if result.status == "success" and not https_verified:
        result.status = "partial"
        
    return result.model_dump(by_alias=True)
