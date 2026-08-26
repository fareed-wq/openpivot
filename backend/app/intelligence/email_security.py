from datetime import datetime, timezone
import dns.resolver
import dns.exception
from app.models.email_security import (
    EmailSecurityIntelligenceResult,
    SPFIntelligence,
    DMARCIntelligence,
    MXIntelligence,
    MXRecord
)
from app.intelligence.dns import collect_dns_intelligence, DNS_TIMEOUT, DNS_LIFETIME

def get_mx_provider(host: str) -> str | None:
    host_lower = host.lower()
    if "google.com" in host_lower or "googlemail.com" in host_lower:
        return "Google"
    if "outlook.com" in host_lower or "protection.outlook.com" in host_lower:
        return "Microsoft"
    if "zoho.com" in host_lower:
        return "Zoho"
    if "protonmail.ch" in host_lower or "protonmail.com" in host_lower:
        return "Proton"
    return None

def collect_email_security(domain: str, dns_data: dict = None) -> dict:
    if not dns_data:
        dns_data = collect_dns_intelligence(domain)
        
    mx_status = "absent"
    mx_records = []
    has_hard_error = False
    
    dns_mx = dns_data.get("records", {}).get("MX", {})
    if dns_mx.get("status") == "success" and dns_mx.get("values"):
        mx_status = "present"
        for val in dns_mx["values"]:
            provider = get_mx_provider(val["host"])
            mx_records.append(MXRecord(
                priority=val["priority"],
                host=val["host"],
                provider=provider
            ))
    elif dns_mx.get("status") in ("no_answer", "nxdomain"):
        mx_status = "absent"
    elif dns_mx.get("status") in ("timeout", "error"):
        mx_status = "unavailable"
        has_hard_error = True

    spf_status = "absent"
    spf_record = None
    
    dns_txt = dns_data.get("records", {}).get("TXT", {})
    if dns_txt.get("status") == "success" and dns_txt.get("values"):
        for val in dns_txt["values"]:
            if val.strip().lower().startswith("v=spf1"):
                spf_status = "present"
                spf_record = val.strip()
                break
    elif dns_txt.get("status") in ("no_answer", "nxdomain"):
        spf_status = "absent"
    elif dns_txt.get("status") in ("timeout", "error"):
        spf_status = "unavailable"
        has_hard_error = True

    dmarc_status = "absent"
    dmarc_record = None
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt_data = b"".join(rdata.strings).decode('utf-8', errors='replace')
            if txt_data.strip().lower().startswith("v=dmarc1"):
                dmarc_status = "present"
                dmarc_record = txt_data.strip()
                break
    except dns.resolver.NoAnswer:
        dmarc_status = "absent"
    except dns.resolver.NXDOMAIN:
        dmarc_status = "absent"
    except (dns.exception.Timeout, dns.resolver.NoNameservers, Exception):
        dmarc_status = "unavailable"
        has_hard_error = True
        
    statuses = [mx_status, spf_status, dmarc_status]
    if all(s == "unavailable" for s in statuses):
        overall_status = "error"
    elif "unavailable" in statuses:
        overall_status = "partial"
    else:
        overall_status = "success"

    result = EmailSecurityIntelligenceResult(
        collector="email_security",
        domain=domain,
        status=overall_status,
        queried_at=datetime.now(timezone.utc).isoformat(),
        spf=SPFIntelligence(status=spf_status, record=spf_record),
        dmarc=DMARCIntelligence(status=dmarc_status, record=dmarc_record),
        mx=MXIntelligence(status=mx_status, records=mx_records)
    )
    
    return result.model_dump()
