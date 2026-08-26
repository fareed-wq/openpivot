import ipaddress
import re

def validate_and_normalize_target(original_target: str) -> dict:
    target = original_target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    
    if "://" in target:
        raise ValueError("URL schemes are not supported.")
    if "/" in target or "?" in target or "#" in target:
        raise ValueError("Paths, query strings, and fragments are not supported.")
    if ":" in target:
        raise ValueError("Ports are not supported.")

    parts = target.split('.')
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        try:
            ip = ipaddress.IPv4Address(target)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or not ip.is_global:
                raise ValueError("Only public, globally routable IPv4 addresses are permitted.")
            return {
                "input": original_target,
                "normalized": str(ip),
                "type": "ipv4",
                "valid": True
            }
        except ipaddress.AddressValueError:
            raise ValueError("Malformed IPv4 address.")
    
    domain = target.lower()
    if domain.endswith('.'):
        domain = domain[:-1]
    
    if not domain:
        raise ValueError("Target cannot be empty.")
    
    if domain == "localhost":
        raise ValueError("localhost is not supported.")
    
    if len(domain) > 253:
        raise ValueError("Domain length exceeds maximum allowed length.")
        
    labels = domain.split('.')
    if len(labels) < 2:
        raise ValueError("Single-label domains are not supported.")
        
    for label in labels:
        if not label:
            raise ValueError("Empty labels are not permitted.")
        if len(label) > 63:
            raise ValueError("Label length exceeds maximum allowed length.")
        if label.startswith('-') or label.endswith('-'):
            raise ValueError("Labels cannot start or end with a hyphen.")
        if not re.match(r'^[a-z0-9\-]+$', label):
            raise ValueError("Domain contains invalid characters.")

    return {
        "input": original_target,
        "normalized": domain,
        "type": "domain",
        "valid": True
    }
