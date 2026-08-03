"""Discovery path: parseContent / checkPatternsInList / fetchSource."""

import base64
import json

import pytest
import requests

import proxyUtil.net as net
import proxyUtil.parsers as parsers
from proxyUtil.net import FetchResult, ScrapURL, ScrapURLs, fetchSource
from proxyUtil.parsers import checkPatternsInList, parseContent, tagChanger
from proxyUtil.schemes import ss_scheme, vmess_scheme


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_checkPatternsInList_keeps_every_proxy_on_a_line():
    lines = ["vless://a@h:443 trojan://b@h:443 ss://Y2M6cHc@h:443"]
    out = checkPatternsInList(lines)
    assert out == ["vless://a@h:443", "trojan://b@h:443", "ss://Y2M6cHc@h:443"]


def test_checkPatternsInList_respects_pattern_filter():
    lines = ["vless://a@h:443 ss://Y2M6cHc@h:443"]
    assert checkPatternsInList(lines, [ss_scheme]) == ["ss://Y2M6cHc@h:443"]


def test_checkPatternsInList_ignores_embedded_matches():
    # A scheme must start a token; `href="vmess://..."` is not a bare proxy.
    assert checkPatternsInList(['<a href="vmess://abcd">']) == []


def test_parseContent_decodes_whole_body_base64_subscription():
    plain = "vless://id@example.com:443?security=tls#old\ntrojan://pw@example.com:443"
    assert parseContent(b64(plain)) == plain.splitlines()


def test_parseContent_decodes_multiline_base64_subscription():
    # Subscriptions are frequently served wrapped at 64/76 columns.
    plain = "vless://id@example.com:443#a\ntrojan://pw@example.com:443#b"
    blob = b64(plain)
    wrapped = "\n".join(blob[i : i + 40] for i in range(0, len(blob), 40))
    assert parseContent(wrapped) == plain.splitlines()


def test_parseContent_decodes_one_base64_blob_per_line():
    # Aggregators concatenate whole subscriptions, one encoded blob per line.
    first, second = "vless://id@example.com:443#a", "trojan://pw@example.com:443#b"
    assert parseContent(f"{b64(first)}\n{b64(second)}") == [first, second]


def test_parseContent_ignores_a_bom_in_the_middle_of_the_body():
    first, second = "vless://id@example.com:443#a", "trojan://pw@example.com:443#b"
    assert parseContent(f"{b64(first)}\n﻿{b64(second)}") == [first, second]


def test_parseContent_reads_shadowsocks_json_array():
    payload = json.dumps(
        [{"method": "aes-256-gcm", "password": "pw", "server": "h", "server_port": 8388}]
    )
    out = parseContent(payload)
    assert len(out) == 1
    assert out[0].startswith(ss_scheme)


def test_parseContent_ignores_json_object_that_is_not_a_shadow_list():
    # Valid JSON, but processShadowJson only speaks list-of-servers.
    assert parseContent('{"servers": 1}') == []


def test_parseContent_survives_base64_that_is_not_utf8():
    assert parseContent("__8=") == []


def test_parseContent_strips_bom_and_blank_bodies():
    assert parseContent("﻿   \n\n") == []


def test_parseContent_does_not_base64_decode_plain_proxy_lines(monkeypatch):
    """The fast path must never pay for base64 work on ordinary proxy lines."""
    calls = []
    monkeypatch.setattr(parsers, "base64Decode", lambda s: calls.append(s) or "")
    body = "\n".join(f"vless://id{i}@example.com:443#n{i}" for i in range(500))
    assert len(parseContent(body)) == 500
    assert calls == []


def test_tagChanger_raises_on_malformed_vmess():
    # Silently handing back an untagged URL let callers publish bad configs.
    with pytest.raises(ValueError):
        tagChanger(f"{vmess_scheme}not-base64-!!", "tag")


def test_tagChanger_passes_through_schemes_without_a_tag_slot():
    url = "naive+https://user:pw@example.com:443"
    assert tagChanger(url, "tag") == url


class _FakeResponse:
    def __init__(self, chunks, status=200, encoding="utf-8"):
        self._chunks = chunks
        self.status_code = status
        self.encoding = encoding

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status_code // 100 != 2:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)

    def iter_content(self, chunk_size=None):
        yield from self._chunks


def _patch_get(monkeypatch, response):
    def fake_get(url, **kwargs):
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(net.requests, "get", fake_get)


def test_fetchSource_returns_structured_result(monkeypatch):
    body = b"vless://id@example.com:443#a\n"
    _patch_get(monkeypatch, _FakeResponse([body]))
    result = fetchSource("https://example.com/sub")
    assert isinstance(result, FetchResult)
    assert result.has_proxies and result.reachable
    assert result.proxies == ("vless://id@example.com:443#a",)
    assert result.http_status == 200
    assert result.bytes_downloaded == len(body)
    assert result.error is None


def test_fetchSource_enforces_size_cap(monkeypatch):
    _patch_get(monkeypatch, _FakeResponse([b"x" * 1024] * 8))
    result = fetchSource("https://example.com/big", max_bytes=2048)
    assert not result.has_proxies
    assert "exceeds" in result.error
    assert result.proxies == ()


def test_fetchSource_reports_http_error_status(monkeypatch):
    _patch_get(monkeypatch, _FakeResponse([], status=404))
    result = fetchSource("https://example.com/missing")
    assert not result.has_proxies
    assert result.http_status == 404
    assert result.error == "HTTP 404"


def test_fetchSource_reports_transport_error(monkeypatch):
    _patch_get(monkeypatch, requests.ConnectionError("boom"))
    result = fetchSource("https://example.invalid/x")
    assert not result.has_proxies and not result.reachable
    assert result.http_status is None
    assert "ConnectionError" in result.error


def test_ScrapURL_stays_a_plain_list_of_proxies(monkeypatch):
    _patch_get(monkeypatch, _FakeResponse([b"vless://id@example.com:443#a\n"]))
    assert ScrapURL("https://example.com/sub") == ["vless://id@example.com:443#a"]


def test_ScrapURL_returns_empty_list_on_failure(monkeypatch):
    _patch_get(monkeypatch, requests.ConnectionError("boom"))
    assert ScrapURL("https://example.invalid/x") == []


def test_ScrapURLs_preserves_input_order(monkeypatch):
    def fake_fetch(url, patterns=None, **kwargs):
        return FetchResult(url=url, http_status=200)

    monkeypatch.setattr(net, "fetchSource", fake_fetch)
    urls = [f"https://example.com/{i}" for i in range(20)]
    assert [r.url for r in ScrapURLs(urls, workers=8)] == urls


def test_ScrapURLs_handles_empty_input():
    assert ScrapURLs([]) == []
