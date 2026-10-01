"""geo + speedtest against a local HTTP server reached through the fake SOCKS core."""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from proxyUtil import geo, speedtest
from proxyUtil._common import find_free_ports
from proxyUtil.probe import socks_proxies
from proxyUtil.runner import CoreProcess
from tests.helpers import FAKE_CORE

TRACE = "fl=1\nip=203.0.113.9\nloc=DE\ncolo=FRA\n"


class Handler(BaseHTTPRequestHandler):
    throttle = 0.0  # seconds slept between 64 KB chunks of a download

    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/cdn-cgi/trace":
            body = TRACE.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/__down":
            total = int(dict(p.split("=") for p in query.split("&"))["bytes"])
            self.send_response(200)
            self.send_header("Content-Length", str(total))
            self.end_headers()
            sent = 0
            try:
                while sent < total:
                    n = min(65536, total - sent)
                    self.wfile.write(b"x" * n)
                    sent += n
                    time.sleep(type(self).throttle)
            except OSError:
                pass  # client hung up at its cap
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        if self.headers.get("Transfer-Encoding") == "chunked":
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                self.rfile.read(size)
                self.rfile.readline()
        else:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def world(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    http_port = server.server_address[1]
    (port,) = find_free_ports(29000, 1)
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"port": port, "mode": "serve", "target": ["127.0.0.1", http_port]}))
    with CoreProcess([sys.executable, FAKE_CORE, str(cfg)], port) as core:
        core.wait_ready(5)
        yield socks_proxies(port), "http://speed.test"
    server.shutdown()
    Handler.throttle = 0.0


@pytest.mark.parametrize(
    ("cc", "expected"),
    [
        ("DE", "🇩🇪"),
        ("us", "🇺🇸"),
        ("IR", "🇮🇷"),
        (None, "🏳"),
        ("", "🏳"),
        ("XX", "🏳"),
        ("T1", "🏳"),
        ("DEU", "🏳"),
    ],
)
def test_flag(cc, expected):
    assert geo.flag(cc) == expected


def test_parse_trace():
    assert geo.parse_trace(TRACE)["loc"] == "DE"
    assert geo.parse_trace("garbage") == {}


def test_lookup_exit_uses_trace_through_the_proxy(world):
    proxies, base = world
    info = geo.lookup_exit(proxies, 3, trace_url=f"{base}/cdn-cgi/trace")
    assert info == geo.ExitInfo("203.0.113.9", "DE")


def test_lookup_falls_back_when_trace_fails(world):
    proxies, base = world
    info = geo.lookup_exit(
        proxies, 3, trace_url=f"{base}/nope", fallback=lambda *_: ("198.51.100.1", "France", "FR")
    )
    assert info == geo.ExitInfo("198.51.100.1", "FR", "France")
    dead = geo.lookup_exit(
        proxies, 3, trace_url=f"{base}/nope", fallback=lambda *_: (None, None, None)
    )
    assert dead is None


def test_measure_latency_warms_up_and_reports_jitter(world):
    proxies, base = world
    stats = speedtest.measure_latency(f"{base}/x", proxies, samples=5, timeout=3)
    assert stats.ok == 5 and stats.total == 5 and stats.median_ms >= 0 and stats.jitter_ms >= 0


def test_measure_latency_none_when_unreachable():
    (port,) = find_free_ports(29500, 1)
    assert speedtest.measure_latency("http://x/", socks_proxies(port), samples=2, timeout=1) is None


def test_download_is_capped_by_bytes_and_reports_mbps(world):
    proxies, base = world
    started = time.perf_counter()
    mbps = speedtest.measure_download(proxies, base=base, max_bytes=2 * 1024 * 1024, max_seconds=5)
    assert mbps and mbps > 1  # loopback is fast
    assert time.perf_counter() - started < 5


def test_download_is_capped_by_time(world):
    proxies, base = world
    Handler.throttle = 0.05  # ~1.3 MB/s: a 50 MB download could never finish in time
    started = time.perf_counter()
    mbps = speedtest.measure_download(proxies, base=base, max_bytes=50 * 1024 * 1024, max_seconds=1)
    assert 1 <= time.perf_counter() - started < 4
    assert mbps and 1 < mbps < 100  # throttled, so the time cap (not bytes) ended it


def test_download_failure_is_none(world):
    proxies, _ = world
    assert (
        speedtest.measure_download(proxies, base="http://speed.test/missing", max_bytes=1) is None
    )


def test_upload_is_capped_and_reports_mbps(world):
    proxies, base = world
    mbps = speedtest.measure_upload(proxies, base=base, max_bytes=1024 * 1024, max_seconds=5)
    assert mbps and mbps > 0
