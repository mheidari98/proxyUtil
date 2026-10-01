"""Probe status rules and real-millisecond latency, via the fake SOCKS core."""

import json
import sys

import pytest

from proxyUtil._common import find_free_ports
from proxyUtil.probe import probe_liveness, socks_proxies
from proxyUtil.runner import CoreProcess
from tests.helpers import FAKE_CORE, start_http


@pytest.fixture
def socks(tmp_path):
    server, http_port = start_http(delay=0.05)
    (port,) = find_free_ports(31000, 1)
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"port": port, "mode": "serve", "target": ["127.0.0.1", http_port]}))
    with CoreProcess([sys.executable, FAKE_CORE, str(cfg)], port) as core:
        core.wait_ready(5)
        yield socks_proxies(port)
    server.shutdown()


def test_generate_204_must_be_exactly_204(socks):
    res = probe_liveness("http://www.gstatic.com/generate_204", socks, 3)
    assert res.ok and res.status_code == 204
    assert 40 <= res.latency_ms < 3000  # milliseconds, not 10ms units


def test_error_status_is_not_alive(socks):
    res = probe_liveness("http://example.test/forbidden", socks, 3)
    assert not res.ok and res.error == "HTTP 403"


def test_custom_target_accepts_2xx(socks):
    assert probe_liveness("http://example.test/ok", socks, 3).ok


def test_204_endpoint_rejects_200(socks):
    # a captive portal answering 200 for generate_204 is not a working proxy
    assert not probe_liveness("http://example.test/ok/generate_204", socks, 3).ok


def test_dead_port_is_not_alive():
    (port,) = find_free_ports(31500, 1)
    res = probe_liveness("http://www.gstatic.com/generate_204", socks_proxies(port), 1)
    assert not res.ok and res.error
