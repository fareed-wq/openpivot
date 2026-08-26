import ssl
import socket
import binascii
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from app.core.network_safety import resolve_safe_addresses, NetworkSafetyError
from app.models.tls import TLSIntelligenceResult, TLSVerification, TLSCertificate

CONNECT_TIMEOUT = 4.0

def _get_name_string(name: x509.Name) -> str:
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts) if parts else str(name)

def _parse_certificate(der_data: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der_data, default_backend())
    
    subject = _get_name_string(cert.subject)
    issuer = _get_name_string(cert.issuer)
    
    san_dns = []
    san_ip = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                dns_val = name.value.lower()
                if dns_val.endswith("."):
                    dns_val = dns_val[:-1]
                if dns_val not in san_dns:
                    san_dns.append(dns_val)
            elif isinstance(name, x509.IPAddress):
                ip_str = str(name.value)
                if ip_str not in san_ip:
                    san_ip.append(ip_str)
    except x509.ExtensionNotFound:
        pass

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        
    now = datetime.now(timezone.utc)
    currently_valid = not_before <= now <= not_after
    days_until_expiry = (not_after - now).days
    
    fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode('utf-8').upper()
    fingerprint = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))

    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": str(cert.serial_number),
        "version": cert.version.name,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "currently_valid": currently_valid,
        "days_until_expiry": days_until_expiry,
        "sha256_fingerprint": fingerprint,
        "san_dns": san_dns,
        "san_ip": san_ip
    }

def _connect_and_get_cert(ip: str, domain: str, verify: bool):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
    sock = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    
    try:
        sock.connect((ip, 443))
        ssock = context.wrap_socket(sock, server_hostname=domain)
        
        der_cert = ssock.getpeercert(binary_form=True)
        tls_version = ssock.version()
        cipher = ssock.cipher()[0] if ssock.cipher() else None
        
        ssock.close()
        return der_cert, tls_version, cipher, None
    except ssl.SSLCertVerificationError as e:
        return None, None, None, e.verify_message
    except ssl.SSLError as e:
        return None, None, None, f"SSL Error: {str(e)}"
    except socket.timeout:
        raise
    except ConnectionRefusedError:
        raise
    except Exception as e:
        raise
    finally:
        sock.close()

def collect_tls_intelligence(domain: str) -> dict:
    try:
        ips = resolve_safe_addresses(domain)
    except NetworkSafetyError as e:
        if "DNS resolution failed" in str(e):
            return TLSIntelligenceResult(domain=domain, status="unavailable", queried_at=datetime.now(timezone.utc).isoformat()).model_dump()
        else:
            return TLSIntelligenceResult(domain=domain, status="blocked", queried_at=datetime.now(timezone.utc).isoformat()).model_dump()

    last_status = "error"
    for ip_to_use in ips:
        result = TLSIntelligenceResult(
            domain=domain,
            status="error",
            queried_at=datetime.now(timezone.utc).isoformat(),
            peer_ip=ip_to_use
        )
        
        try:
            der_cert, tls_ver, cipher, verify_err = _connect_and_get_cert(ip_to_use, domain, verify=True)
            
            if verify_err and not verify_err.startswith("SSL Error:"):
                der_cert, tls_ver, cipher, _ = _connect_and_get_cert(ip_to_use, domain, verify=False)
                if not der_cert:
                    last_status = "unavailable"
                    continue  # Try next IP
                    
                try:
                    cert_data = _parse_certificate(der_cert)
                except ValueError:
                    last_status = "error"
                    continue
                    
                result.status = "partial"
                result.tls_version = tls_ver
                result.cipher = cipher
                result.verification = TLSVerification(status="failed", reason=verify_err)
                result.certificate = TLSCertificate(**cert_data)
                return result.model_dump()
                
            if not der_cert:
                last_status = "unavailable"
                continue  # Try next IP
                
            try:
                cert_data = _parse_certificate(der_cert)
            except ValueError:
                last_status = "error"
                continue
                
            result.status = "success"
            result.tls_version = tls_ver
            result.cipher = cipher
            result.verification = TLSVerification(status="verified")
            result.certificate = TLSCertificate(**cert_data)
            return result.model_dump()
            
        except socket.timeout:
            last_status = "timeout"
            continue
        except ConnectionRefusedError:
            last_status = "unavailable"
            continue
        except OSError:
            last_status = "unavailable"
            continue
            
    # All validated addresses failed
    result.status = last_status
    return result.model_dump()
