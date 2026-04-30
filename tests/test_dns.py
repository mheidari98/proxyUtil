"""Unit tests for DNS-related table data in proxyUtil.dnsUrl."""

from proxyUtil.dnsUrl import Do53_URLS, DoH_URLS, DoT_URLS
from proxyUtil.dnsUtil import RR


def test_dns_tables_have_cloudflare_and_google():
    for table in (Do53_URLS, DoT_URLS, DoH_URLS):
        keys_lower = " ".join(table.keys()).lower()
        assert "cloudflare" in keys_lower
        assert "google" in keys_lower
        assert all(isinstance(v, list) and v for v in table.values())


def test_doh_urls_are_https_endpoints():
    for endpoints in DoH_URLS.values():
        for ep in endpoints:
            assert ep.startswith("https://"), f"bad DoH endpoint {ep!r}"


def test_dot_urls_are_tls_endpoints():
    for endpoints in DoT_URLS.values():
        for ep in endpoints:
            assert ep.startswith("tls://"), f"bad DoT endpoint {ep!r}"


def test_do53_urls_are_addr_only():
    for endpoints in Do53_URLS.values():
        for ep in endpoints:
            assert "://" not in ep, f"Do53 endpoint should be plain addr, got {ep!r}"


def test_RR_constants():
    assert "A" in RR
    assert "AAAA" in RR
    assert "CNAME" in RR
