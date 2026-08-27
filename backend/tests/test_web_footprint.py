import pytest
from app.intelligence.web_footprint import extract_web_metadata, detect_technologies, build_web_footprint


# ---------------------------------------------------------------------------
# Web Metadata extraction tests
# ---------------------------------------------------------------------------

class TestExtractWebMetadata:
    def test_full_metadata(self):
        html = b"""
        <html lang="en">
        <head>
            <title>Example Site - Home</title>
            <meta name="description" content="An example website for testing.">
            <meta name="generator" content="WordPress 6.4">
            <link rel="canonical" href="https://example.com/">
            <link rel="icon" href="/favicon.ico">
        </head>
        <body>Hello</body>
        </html>
        """
        meta = extract_web_metadata(html)
        assert meta["title"] == "Example Site - Home"
        assert meta["description"] == "An example website for testing."
        assert meta["generator"] == "WordPress 6.4"
        assert meta["canonical_url"] == "https://example.com/"
        assert meta["favicon_url"] == "/favicon.ico"
        assert meta["language"] == "en"

    def test_missing_metadata(self):
        html = b"<html><head></head><body>Hello</body></html>"
        meta = extract_web_metadata(html)
        assert "description" not in meta
        assert "generator" not in meta
        assert "canonical_url" not in meta

    def test_empty_bytes(self):
        meta = extract_web_metadata(b"")
        assert meta == {}

    def test_title_truncation(self):
        long_title = "A" * 1000
        html = f"<html><head><title>{long_title}</title></head></html>".encode()
        meta = extract_web_metadata(html)
        assert len(meta["title"]) == 512

    def test_relative_url_resolution(self):
        html = b'''
        <html><head>
            <link rel="canonical" href="/about">
            <link rel="icon" href="/img/icon.png">
        </head></html>
        '''
        meta = extract_web_metadata(html, final_url="https://example.com/page")
        assert meta["canonical_url"] == "https://example.com/about"
        assert meta["favicon_url"] == "https://example.com/img/icon.png"

    def test_javascript_scheme_rejected(self):
        html = b'''
        <html><head>
            <link rel="canonical" href="javascript:alert(1)">
            <link rel="icon" href="data:image/png;base64,abc">
        </head></html>
        '''
        meta = extract_web_metadata(html, final_url="https://example.com/")
        assert "canonical_url" not in meta
        assert "favicon_url" not in meta


# ---------------------------------------------------------------------------
# Technology detection tests
# ---------------------------------------------------------------------------

class TestDetectTechnologies:
    def test_cloudflare_header(self):
        headers = {"cf-ray": "abc123-IAD", "server": "cloudflare"}
        techs = detect_technologies(headers, b"<html></html>")
        names = [t["name"] for t in techs]
        assert "Cloudflare" in names
        cf = next(t for t in techs if t["name"] == "Cloudflare")
        assert cf["confidence"] == "high"
        assert cf["category"] == "CDN / Proxy"

    def test_nginx_server(self):
        headers = {"server": "nginx/1.25.3"}
        techs = detect_technologies(headers, b"<html></html>")
        names = [t["name"] for t in techs]
        assert "Nginx" in names

    def test_wordpress_from_html(self):
        headers = {}
        html = b'<html><head></head><body><script src="/wp-content/themes/test/app.js"></script></body></html>'
        techs = detect_technologies(headers, html)
        names = [t["name"] for t in techs]
        assert "WordPress" in names

    def test_nextjs_detection(self):
        headers = {"x-powered-by": "Next.js"}
        techs = detect_technologies(headers, b"<html></html>")
        names = [t["name"] for t in techs]
        assert "Next.js" in names

    def test_google_analytics_detection(self):
        headers = {}
        html = b'<html><script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script></html>'
        techs = detect_technologies(headers, html)
        names = [t["name"] for t in techs]
        assert "Google Analytics" in names

    def test_deduplicate(self):
        headers = {"server": "cloudflare", "cf-ray": "abc123"}
        techs = detect_technologies(headers, b"<html></html>")
        cf_count = sum(1 for t in techs if t["name"] == "Cloudflare")
        assert cf_count == 1

    def test_no_false_positives_empty(self):
        headers = {}
        techs = detect_technologies(headers, b"<html><body>Hello World</body></html>")
        assert len(techs) == 0

    def test_html_only_detection_never_high_confidence(self):
        headers = {}
        html = b'<html><body><script>Drupal.settings = {}</script></body></html>'
        techs = detect_technologies(headers, html)
        drupal = [t for t in techs if t["name"] == "Drupal"]
        assert len(drupal) == 1
        assert drupal[0]["confidence"] == "medium"

    def test_multiple_technologies(self):
        headers = {"server": "nginx/1.25", "x-powered-by": "PHP/8.2", "cf-ray": "abc"}
        html = b'<html><script src="https://www.googletagmanager.com/gtag/js"></script></html>'
        techs = detect_technologies(headers, html)
        names = [t["name"] for t in techs]
        assert "Nginx" in names
        assert "PHP" in names
        assert "Cloudflare" in names
        assert "Google Analytics" in names


# ---------------------------------------------------------------------------
# build_web_footprint integration tests
# ---------------------------------------------------------------------------

class TestBuildWebFootprint:
    def test_full_build(self):
        headers = {"server": "nginx/1.25", "cf-ray": "abc123"}
        html = b"""
        <html lang="en">
        <head>
            <title>Test Page</title>
            <meta name="description" content="Test description">
        </head>
        <body></body>
        </html>
        """
        result = build_web_footprint(headers, html)
        assert "metadata" in result
        assert "technologies" in result
        assert "technology_count" in result
        assert result["metadata"]["title"] == "Test Page"
        assert result["technology_count"] >= 2  # nginx + cloudflare

    def test_empty_html(self):
        result = build_web_footprint({}, b"")
        assert result["metadata"] == {}
        assert result["technologies"] == []
        assert result["technology_count"] == 0

    def test_bounded_processing(self):
        # Ensure very large HTML doesn't crash
        huge_html = b"<html><body>" + b"x" * 300000 + b"</body></html>"
        result = build_web_footprint({}, huge_html)
        assert isinstance(result["technologies"], list)
