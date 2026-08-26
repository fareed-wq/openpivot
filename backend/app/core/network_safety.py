import socket
import ipaddress
from typing import List

MAX_CONNECTION_ADDRESSES = 3

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
