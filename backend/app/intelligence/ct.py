import httpx
from typing import Dict, Any, List

def collect_ct_assets(domain: str) -> Dict[str, Any]:
    """
    Passively discover subdomains using Certificate Transparency logs via crt.sh.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    result = {
        "status": "pending",
        "source": "crt.sh",
        "hostnames": [],
        "count": 0,
        "truncated": False,
        "error": None
    }
    
    try:
        import json
        
        response_bytes = bytearray()
        MAX_BYTES = 5 * 1024 * 1024 # 5 MB limit
        
        with httpx.stream("GET", url, timeout=10.0) as r:
            if r.status_code != 200:
                result["status"] = "error"
                result["error"] = f"HTTP {r.status_code}"
                return result
                
            for chunk in r.iter_bytes():
                response_bytes.extend(chunk)
                if len(response_bytes) > MAX_BYTES:
                    result["status"] = "error"
                    result["error"] = "CT response exceeded 5MB size limit"
                    return result
                    
        data = json.loads(response_bytes.decode('utf-8'))
        if not isinstance(data, list):
            result["status"] = "error"
            result["error"] = "Invalid response format"
            return result
            
        raw_names = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            # name_value can contain multiple hostnames separated by newlines
            for line in name_value.splitlines():
                line = line.strip().lower()
                if line.endswith("."):
                    line = line[:-1]
                
                # Strip wildcard prefix
                if line.startswith("*."):
                    line = line[2:]
                    
                # Ensure it actually belongs to the domain
                if line == domain or line.endswith(f".{domain}"):
                    if line:
                        raw_names.add(line)
                        
        sorted_names = sorted(list(raw_names))
        
        if len(sorted_names) > 100:
            result["hostnames"] = sorted_names[:100]
            result["truncated"] = True
        else:
            result["hostnames"] = sorted_names
            
        result["count"] = len(result["hostnames"])
        result["status"] = "success"
        
    except httpx.TimeoutException:
        result["status"] = "timeout"
        result["error"] = "CT log source timed out"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Unexpected error: {str(e)}"
        
    return result
