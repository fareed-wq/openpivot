import socket
import ipaddress
import http.client
import urllib.parse
import ssl
import json
from typing import List, Optional

MAX_CONNECTION_ADDRESSES = 3
MAX_JSON_RESPONSE_BYTES = 5 * 1024 * 1024  # 5MB limit

class NetworkSafetyError(Exception):
    pass

def _is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.is_site_local:
                return False
        return True
    except ValueError:
        return False

def resolve_safe_addresses(domain: str) -> List[str]:
    try:
        addr_info = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise NetworkSafetyError("DNS resolution failed")

    safe_ips = []
    for info in addr_info:
        ip_str = info[4][0]
        if ip_str not in safe_ips and _is_safe_ip(ip_str):
            safe_ips.append(ip_str)
            if len(safe_ips) >= MAX_CONNECTION_ADDRESSES:
                break

    if not safe_ips:
        raise NetworkSafetyError("No globally routable public addresses found")

    return safe_ips

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

def safe_fetch_json(url: str, max_redirects: int = 3, connect_timeout: float = 3.0, read_timeout: float = 5.0) -> dict:
    current_url = url
    redirects = 0

    while redirects <= max_redirects:
        try:
            parsed = urllib.parse.urlparse(current_url)
            hostname = parsed.hostname
            if not hostname:
                return {"status": "error"}

            scheme = parsed.scheme
            if scheme not in ("http", "https"):
                return {"status": "error"}

            if parsed.username or parsed.password:
                return {"status": "error"}

            # Allow only standard ports
            if parsed.port is not None and parsed.port not in (80, 443):
                return {"status": "error"}

            # Resolve safe IPs
            ips = resolve_safe_addresses(hostname)
        except NetworkSafetyError:
            return {"status": "error"}
        except Exception:
            return {"status": "error"}

        last_err = "error"
        resp = None
        peer_ip = None

        for ip in ips:
            try:
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    conn = SafeHTTPSConnection(ip, hostname, timeout=connect_timeout, context=ctx)
                else:
                    conn = SafeHTTPConnection(ip, hostname, timeout=connect_timeout)

                path = parsed.path if parsed.path else "/"
                if parsed.query:
                    path += "?" + parsed.query

                headers = {
                    "Host": hostname,
                    "User-Agent": "OpenPivot/0.1",
                    "Connection": "close",
                    "Accept": "application/rdap+json, application/json, text/json"
                }
                conn.request("GET", path, headers=headers)

                if getattr(conn, 'sock', None):
                    conn.sock.settimeout(read_timeout)

                resp = conn.getresponse()
                peer_ip = ip
                break
            except socket.timeout:
                last_err = "timeout"
            except Exception as e:
                last_err = "error"

        if resp is None:
            return {"status": last_err}

        status_code = resp.status
        if status_code in (301, 302, 303, 307, 308):
            loc = resp.getheader("Location")
            resp.close()
            if not loc:
                return {"status": "error"}

            current_url = urllib.parse.urljoin(current_url, loc)
            redirects += 1
            continue

        if status_code == 200:
            try:
                body = resp.read(MAX_JSON_RESPONSE_BYTES + 1)
                if len(body) > MAX_JSON_RESPONSE_BYTES:
                    return {"status": "error"}
                data = json.loads(body.decode('utf-8'))
                return {"status": "success", "data": data, "source": current_url}
            except Exception:
                return {"status": "error"}
        elif status_code == 404:
            return {"status": "not_found"}
        elif status_code == 429:
            return {"status": "rate_limited"}
        elif status_code >= 500:
            return {"status": "error"}
        else:
            return {"status": "error"}

    return {"status": "error"}
