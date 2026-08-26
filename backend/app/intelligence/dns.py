import dns.resolver
from dns.exception import DNSException
from datetime import datetime, timezone
from app.models.dns import DNSIntelligenceResult, DNSRecordResult

DNS_TIMEOUT = 2.0
DNS_LIFETIME = 3.0

def collect_dns_intelligence(domain: str) -> dict:
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    
    records = {}
    has_hard_error = False
    has_success = False

    for rtype in record_types:
        record_res = DNSRecordResult(status="error", values=[], error=None)
        try:
            answers = resolver.resolve(domain, rtype)
            values = []
            for rdata in answers:
                if rtype in ("A", "AAAA"):
                    values.append(rdata.to_text())
                elif rtype in ("NS", "CNAME"):
                    val = rdata.target.to_text()
                    if val.endswith('.'):
                        val = val[:-1]
                    values.append(val)
                elif rtype == "MX":
                    host = rdata.exchange.to_text()
                    if host.endswith('.'):
                        host = host[:-1]
                    values.append({"priority": rdata.preference, "host": host})
                elif rtype == "TXT":
                    txt_data = b"".join(rdata.strings).decode('utf-8', errors='replace')
                    values.append(txt_data)
                elif rtype == "CAA":
                    val = rdata.value
                    if isinstance(val, bytes):
                        val = val.decode('utf-8', errors='replace')
                    else:
                        val = str(val)
                    
                    tag = rdata.tag
                    if isinstance(tag, bytes):
                        tag = tag.decode('utf-8', errors='replace')
                    else:
                        tag = str(tag)

                    values.append({
                        "flags": rdata.flags,
                        "tag": tag,
                        "value": val
                    })
            
            record_res.status = "success"
            record_res.values = values
            has_success = True
            
        except dns.resolver.NoAnswer:
            record_res.status = "no_answer"
        except dns.resolver.NXDOMAIN:
            record_res.status = "nxdomain"
            has_hard_error = True
        except dns.exception.Timeout:
            record_res.status = "timeout"
            record_res.error = "DNS query timed out"
            has_hard_error = True
        except dns.resolver.NoNameservers:
            record_res.status = "error"
            record_res.error = "No nameservers found"
            has_hard_error = True
        except Exception as e:
            record_res.status = "error"
            record_res.error = str(e)
            has_hard_error = True
            
        records[rtype] = record_res

    # Determine overall status
    if has_hard_error:
        if has_success:
            overall_status = "partial"
        else:
            overall_status = "error"
    else:
        if has_success:
            overall_status = "success"
        else:
            # If all are no_answer
            overall_status = "success"

    result = DNSIntelligenceResult(
        collector="dns",
        domain=domain,
        status=overall_status,
        queried_at=datetime.now(timezone.utc).isoformat(),
        records=records
    )
    return result.model_dump()
