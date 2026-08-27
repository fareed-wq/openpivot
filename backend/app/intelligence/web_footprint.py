"""
Web Footprint Intelligence — extracts web metadata and technology signals
from an existing HTTP response body + headers.

This module does NOT make its own network requests; it processes raw bytes
and a header dict that have already been fetched by the HTTP metadata collector.
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# Web Metadata extraction (from HTML body)
# ---------------------------------------------------------------------------

def _meta_content(html: str, name_or_prop: str) -> Optional[str]:
    """Extract <meta name="..." content="..."> or <meta property="..." content="...">."""
    pattern = (
        r'<meta\s+[^>]*?(?:name|property)\s*=\s*["\']'
        + re.escape(name_or_prop)
        + r'["\'][^>]*?content\s*=\s*["\']([^"\']{0,1024})["\']'
    )
    m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip() or None
    # Try reversed order: content before name
    pattern2 = (
        r'<meta\s+[^>]*?content\s*=\s*["\']([^"\']{0,1024})["\'][^>]*?(?:name|property)\s*=\s*["\']'
        + re.escape(name_or_prop)
        + r'["\']'
    )
    m2 = re.search(pattern2, html, re.IGNORECASE | re.DOTALL)
    if m2:
        return m2.group(1).strip() or None
    return None


_SAFE_URL_SCHEMES = {"http", "https", ""}


def _resolve_and_validate_url(raw_url: Optional[str], base_url: Optional[str]) -> Optional[str]:
    """Resolve a possibly-relative URL against the base and reject unsafe schemes."""
    if not raw_url:
        return None
    if base_url:
        resolved = urllib.parse.urljoin(base_url, raw_url)
    else:
        resolved = raw_url
    try:
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme.lower() not in _SAFE_URL_SCHEMES:
            return None
    except Exception:
        return None
    return resolved


def extract_web_metadata(html_bytes: bytes, final_url: Optional[str] = None) -> Dict[str, Optional[str]]:
    """Return a dict of factual web metadata extracted from raw HTML."""
    try:
        html = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return {}

    meta: Dict[str, Optional[str]] = {}

    # title — already extracted by the HTTP collector, but we include it here
    # for completeness so the web_footprint result is self-contained.
    title_m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_m:
        t = re.sub(r'\s+', ' ', title_m.group(1)).strip()
        if t:
            meta["title"] = t[:512]

    meta["description"] = _meta_content(html, "description")

    # canonical
    canon_m = re.search(r'<link\s+[^>]*?rel\s*=\s*["\']canonical["\'][^>]*?href\s*=\s*["\']([^"\']{0,2048})["\']', html, re.IGNORECASE)
    if not canon_m:
        canon_m = re.search(r'<link\s+[^>]*?href\s*=\s*["\']([^"\']{0,2048})["\'][^>]*?rel\s*=\s*["\']canonical["\']', html, re.IGNORECASE)
    if canon_m:
        meta["canonical_url"] = _resolve_and_validate_url(canon_m.group(1).strip(), final_url)

    meta["generator"] = _meta_content(html, "generator")

    # favicon
    fav_m = re.search(r'<link\s+[^>]*?rel\s*=\s*["\'](?:icon|shortcut icon)["\'][^>]*?href\s*=\s*["\']([^"\']{0,2048})["\']', html, re.IGNORECASE)
    if not fav_m:
        fav_m = re.search(r'<link\s+[^>]*?href\s*=\s*["\']([^"\']{0,2048})["\'][^>]*?rel\s*=\s*["\'](?:icon|shortcut icon)["\']', html, re.IGNORECASE)
    if fav_m:
        meta["favicon_url"] = _resolve_and_validate_url(fav_m.group(1).strip(), final_url)

    # language — from <html lang="...">
    lang_m = re.search(r'<html[^>]*?\slang\s*=\s*["\']([^"\']{1,32})["\']', html, re.IGNORECASE)
    if lang_m:
        meta["language"] = lang_m.group(1).strip()

    # Remove keys with None values for cleanliness
    return {k: v for k, v in meta.items() if v is not None}


# ---------------------------------------------------------------------------
# Technology detection rules
# ---------------------------------------------------------------------------

# Each rule: (name, category, detector_fn)
# detector_fn(headers, html) -> evidence string or None

_TECH_RULES: List[tuple] = []


def _rule(name: str, category: str):
    """Decorator to register a technology detection rule."""
    def decorator(fn):
        _TECH_RULES.append((name, category, fn))
        return fn
    return decorator


# -- Server / Infrastructure ------------------------------------------------

@_rule("Cloudflare", "CDN / Proxy")
def _detect_cloudflare(headers: Dict[str, str], html: str):
    if headers.get("cf-ray"):
        return f"cf-ray header: {headers['cf-ray'][:64]}"
    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        return f"server header: {headers['server']}"
    return None

@_rule("AWS CloudFront", "CDN / Proxy")
def _detect_cloudfront(headers: Dict[str, str], html: str):
    if headers.get("x-amz-cf-id") or headers.get("x-amz-cf-pop"):
        return "x-amz-cf-id/pop header present"
    via = headers.get("via", "").lower()
    if "cloudfront" in via:
        return f"via header: {headers['via']}"
    return None

@_rule("Akamai", "CDN / Proxy")
def _detect_akamai(headers: Dict[str, str], html: str):
    server = headers.get("server", "").lower()
    if "akamaighost" in server or "akamai" in server:
        return f"server header: {headers['server']}"
    if headers.get("x-akamai-transformed"):
        return "x-akamai-transformed header present"
    return None

@_rule("Fastly", "CDN / Proxy")
def _detect_fastly(headers: Dict[str, str], html: str):
    if headers.get("x-served-by") and headers.get("x-cache"):
        served = headers["x-served-by"]
        if "cache-" in served.lower():
            return f"x-served-by: {served[:64]}"
    via = headers.get("via", "").lower()
    if "varnish" in via:
        return f"via header: {headers['via']}"
    return None

@_rule("Vercel", "Platform")
def _detect_vercel(headers: Dict[str, str], html: str):
    if headers.get("x-vercel-id"):
        return f"x-vercel-id header: {headers['x-vercel-id'][:64]}"
    server = headers.get("server", "").lower()
    if "vercel" in server:
        return f"server header: {headers['server']}"
    return None

@_rule("Netlify", "Platform")
def _detect_netlify(headers: Dict[str, str], html: str):
    if headers.get("x-nf-request-id"):
        return "x-nf-request-id header present"
    server = headers.get("server", "").lower()
    if "netlify" in server:
        return f"server header: {headers['server']}"
    return None

@_rule("Nginx", "Web Server")
def _detect_nginx(headers: Dict[str, str], html: str):
    server = headers.get("server", "").lower()
    if "nginx" in server:
        return f"server header: {headers['server']}"
    return None

@_rule("Apache", "Web Server")
def _detect_apache(headers: Dict[str, str], html: str):
    server = headers.get("server", "").lower()
    if "apache" in server:
        return f"server header: {headers['server']}"
    return None

@_rule("IIS", "Web Server")
def _detect_iis(headers: Dict[str, str], html: str):
    server = headers.get("server", "").lower()
    if "microsoft-iis" in server:
        return f"server header: {headers['server']}"
    return None

# -- Frameworks / CMS -------------------------------------------------------

@_rule("WordPress", "CMS")
def _detect_wordpress(headers: Dict[str, str], html: str):
    if "/wp-content/" in html or "/wp-includes/" in html:
        return "wp-content/wp-includes path in HTML"
    m = re.search(r'<meta\s+name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']WordPress\s*[\d.]*["\']', html, re.IGNORECASE)
    if m:
        return f"generator meta: {m.group(0)[:100]}"
    return None

@_rule("Drupal", "CMS")
def _detect_drupal(headers: Dict[str, str], html: str):
    if headers.get("x-drupal-cache"):
        return "x-drupal-cache header present"
    if headers.get("x-generator", "").lower().startswith("drupal"):
        return f"x-generator header: {headers['x-generator']}"
    if 'Drupal.settings' in html:
        return "Drupal.settings in HTML"
    if '/sites/default/files' in html:
        return "/sites/default/files path in HTML"
    return None

@_rule("Next.js", "Framework")
def _detect_nextjs(headers: Dict[str, str], html: str):
    if headers.get("x-nextjs-cache") or headers.get("x-powered-by", "").lower().startswith("next.js"):
        return f"x-powered-by: {headers.get('x-powered-by', 'x-nextjs-cache header')}"
    if '/_next/' in html:
        return "/_next/ path in HTML"
    return None

@_rule("React", "Framework")
def _detect_react(headers: Dict[str, str], html: str):
    if 'id="__next"' in html or "data-reactroot" in html:
        return "React root element in HTML"
    return None

@_rule("Vue.js", "Framework")
def _detect_vue(headers: Dict[str, str], html: str):
    if 'id="app"' in html and ('Vue.' in html or 'vue.' in html):
        return "Vue.js indicators in HTML"
    if re.search(r'data-v-[a-f0-9]{6,}', html):
        return "Vue scoped style attributes in HTML"
    return None

@_rule("ASP.NET", "Framework")
def _detect_aspnet(headers: Dict[str, str], html: str):
    xp = headers.get("x-powered-by", "").lower()
    if "asp.net" in xp:
        return f"x-powered-by: {headers['x-powered-by']}"
    if headers.get("x-aspnet-version"):
        return f"x-aspnet-version: {headers['x-aspnet-version']}"
    return None

@_rule("PHP", "Language")
def _detect_php(headers: Dict[str, str], html: str):
    xp = headers.get("x-powered-by", "").lower()
    if "php" in xp:
        return f"x-powered-by: {headers['x-powered-by']}"
    return None

# -- Analytics / Tag Managers -----------------------------------------------

@_rule("Google Analytics", "Analytics")
def _detect_ga(headers: Dict[str, str], html: str):
    if "google-analytics.com/analytics.js" in html or "googletagmanager.com/gtag/" in html:
        return "Google Analytics script reference in HTML"
    m = re.search(r'["\'](?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12})["\']', html)
    if m:
        return f"tracking ID: {m.group(0)[:32]}"
    return None

@_rule("Google Tag Manager", "Tag Manager")
def _detect_gtm(headers: Dict[str, str], html: str):
    if "googletagmanager.com/gtm.js" in html:
        return "GTM script reference in HTML"
    m = re.search(r'GTM-[A-Z0-9]{4,10}', html)
    if m:
        return f"GTM container: {m.group(0)}"
    return None

@_rule("Facebook Pixel", "Analytics")
def _detect_fb_pixel(headers: Dict[str, str], html: str):
    if "connect.facebook.net" in html and "fbq(" in html:
        return "Facebook Pixel script + fbq() in HTML"
    return None

@_rule("Hotjar", "Analytics")
def _detect_hotjar(headers: Dict[str, str], html: str):
    if "static.hotjar.com" in html or "hotjar.com/c/hotjar-" in html:
        return "Hotjar script reference in HTML"
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_technologies(headers: Dict[str, str], html_bytes: bytes) -> List[Dict[str, str]]:
    """
    Run all detection rules against the provided headers and HTML body.
    Returns a deduplicated list of detected technologies.
    """
    try:
        html = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html = ""

    seen = set()
    results: List[Dict[str, str]] = []

    for name, category, detector_fn in _TECH_RULES:
        try:
            evidence = detector_fn(headers, html)
        except Exception:
            continue
        if evidence and name not in seen:
            seen.add(name)
            # Confidence based on evidence source
            if "header" in evidence.lower():
                confidence = "high"
            elif "path in HTML" in evidence or "script reference" in evidence:
                confidence = "medium"
            else:
                confidence = "medium"
            results.append({
                "name": name,
                "category": category,
                "evidence": evidence[:256],
                "confidence": confidence,
            })

    return results


def build_web_footprint(headers: Dict[str, str], html_bytes: bytes, final_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Build the complete web footprint result from headers + body.
    This is the main entry point called by the HTTP metadata collector.
    """
    metadata = extract_web_metadata(html_bytes, final_url=final_url)
    technologies = detect_technologies(headers, html_bytes)

    return {
        "metadata": metadata,
        "technologies": technologies,
        "technology_count": len(technologies),
    }
