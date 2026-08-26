import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any

from app.core.target_validation import validate_and_normalize_target
from app.intelligence.dns import collect_dns_intelligence
from app.intelligence.email_security import collect_email_security
from app.intelligence.rdap import collect_domain_rdap
from app.intelligence.tls import collect_tls_intelligence
from app.intelligence.http_metadata import collect_http_metadata
from app.intelligence.ip import collect_ip_intelligence
from app.intelligence.asn import collect_asn_intelligence_from_ip
from app.intelligence.correlation import build_correlations
from app.models.investigation_result import InvestigationResult, TargetInfo

def _safe_execute(collector_name: str, func, *args, **kwargs) -> Dict[str, Any]:
    try:
        return func(*args, **kwargs)
    except Exception:
        return {
            "collector": collector_name,
            "status": "error",
            "error": "Collector failed unexpectedly."
        }

def run_investigation(target_input: str) -> dict:
    t0 = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()
    investigation_id = str(uuid.uuid4())
    
    # Validation throws ValueError for bad inputs
    val_res = validate_and_normalize_target(target_input)
    norm = val_res["normalized"]
    tgt_type = val_res["type"]
    
    target_info = TargetInfo(
        input=val_res["input"],
        normalized=norm,
        type=tgt_type
    )
    
    collectors_data = {}
    collector_status = {}
    
    if tgt_type == "domain":
        # Run Domain collectors
        dns_res = _safe_execute("dns", collect_dns_intelligence, norm)
        collectors_data["dns"] = dns_res
        collector_status["dns"] = dns_res.get("status", "error")
        
        email_res = _safe_execute("email_security", collect_email_security, norm, dns_res)
        collectors_data["email_security"] = email_res
        collector_status["email_security"] = email_res.get("status", "error")
        
        rdap_res = _safe_execute("rdap", collect_domain_rdap, norm)
        collectors_data["rdap"] = rdap_res
        collector_status["rdap"] = rdap_res.get("status", "error")
        
        tls_res = _safe_execute("tls", collect_tls_intelligence, norm)
        collectors_data["tls"] = tls_res
        collector_status["tls"] = tls_res.get("status", "error")
        
        http_res = _safe_execute("http_metadata", collect_http_metadata, norm)
        collectors_data["http_metadata"] = http_res
        collector_status["http_metadata"] = http_res.get("status", "error")
        
    elif tgt_type == "ipv4":
        # Run IPv4 collectors
        ip_res = _safe_execute("ip", collect_ip_intelligence, norm)
        collectors_data["ip"] = ip_res
        collector_status["ip"] = ip_res.get("status", "error")
        
        asn_res = _safe_execute("asn", collect_asn_intelligence_from_ip, norm)
        collectors_data["asn"] = asn_res
        collector_status["asn"] = asn_res.get("status", "error")
        
    else:
        raise ValueError(f"Unsupported target type: {tgt_type}")

    # Determine overall status
    has_full_success = True
    has_usable = False
    
    for st in collector_status.values():
        if st == "success":
            has_usable = True
        elif st == "partial":
            has_usable = True
            has_full_success = False
        else:
            # error, timeout, blocked, etc.
            has_full_success = False
            
    if has_full_success:
        overall_status = "success"
    elif has_usable:
        overall_status = "partial"
    else:
        overall_status = "error"
        
    # Build correlations
    correlation_res = None
    try:
        if tgt_type == "domain":
            correlation_res = build_correlations(
                domain_result={"status": "success", "domain": norm},
                dns_result=collectors_data.get("dns"),
                tls_result=collectors_data.get("tls")
            )
        else:
            correlation_res = build_correlations(
                ip_result=collectors_data.get("ip"),
                asn_result=collectors_data.get("asn")
            )
    except Exception:
        overall_status = "partial" if overall_status == "success" else overall_status
        correlation_res = {"entities": [], "relationships": []}
        
    t1 = time.perf_counter()
    completed_at = datetime.now(timezone.utc).isoformat()
    duration_ms = (t1 - t0) * 1000.0
    
    res = InvestigationResult(
        investigation_id=investigation_id,
        target=target_info,
        status=overall_status,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        collectors=collectors_data,
        collector_status=collector_status,
        correlation=correlation_res
    )
    
    return res.model_dump()
