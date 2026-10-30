"""v2rayChecker orchestration against the fake core: statuses, streaming, Ctrl+C."""

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
import pytest

from proxyUtil.cli import v2rayChecker as vc
from proxyUtil.geo import ExitInfo
from proxyUtil.results import ResultSink
from tests.helpers import start_http

PROBE = "http://www.gstatic.com/generate_204"
ROOT = Path(__file__).resolve().parent.parent


def _cfg(spec, tmp_path, *, timeout=3.0, cancel=None, geo=False):
    return vc.CheckerCfg(
        core=spec,
        binary=spec.binary,
        tempdir=str(tmp_path),
        ready_timeout=5,
        test_url=PROBE,
        timeout=timeout,
        geo=geo,
        cancel=cancel or threading.Event(),
    )


@pytest.fixture
def http():
    server, port = start_http()
    yield port
    server.shutdown()


def test_check_one_statuses(tmp_path, http):
    from tests.helpers import fake_spec

    cfg = _cfg(fake_spec(http), tmp_path, timeout=1)
    live = vc.check_one("ss://a@h:1#serve", 22001, cfg)
    assert live.status == "live" and live.latency_ms >= 0
    crashed = vc.check_one("ss://a@h:1#exit", 22002, cfg)
    assert crashed.status == "config_error" and "unknown cipher" in crashed.error
    assert vc.check_one("hysteria2://x@h:1", 22003, cfg).status == "unsupported"
    cfg.ready_timeout = 0.3
    assert vc.check_one("ss://a@h:1#hang", 22004, cfg).status == "error"


def test_geo_failure_never_drops_a_live_proxy(tmp_path, http, monkeypatch):
    from tests.helpers import fake_spec

    monkeypatch.setattr(vc, "lookup_exit", lambda *_: None)
    res = vc.check_one("ss://a@h:1#serve", 22010, _cfg(fake_spec(http), tmp_path, geo=True))
    assert res.status == "live" and res.country is None


def test_geo_values_are_recorded_when_requested(tmp_path, http, monkeypatch):
    from tests.helpers import fake_spec

    monkeypatch.setattr(vc, "lookup_exit", lambda *_: ExitInfo("1.2.3.4", "DE", "Germany"))
    res = vc.check_one("ss://a@h:1#serve", 22011, _cfg(fake_spec(http), tmp_path, geo=True))
    assert (res.exit_ip, res.country_code) == ("1.2.3.4", "DE")


def test_run_check_streams_all_results_with_shared_queue(tmp_path, http):
    from tests.helpers import fake_spec

    urls = [f"ss://u{i}@h:1#{'serve' if i % 3 else 'exit'}" for i in range(12)]
    out = tmp_path / "out.txt"
    sink = ResultSink(str(out), live=True)
    reporter = vc._Reporter(len(urls), show_bar=False)
    stopped = vc.run_check(urls, _cfg(fake_spec(http), tmp_path), 4, 22100, sink, reporter)
    sink.finalize()
    assert stopped == "done"
    assert reporter.counts["live"] == 8 and reporter.counts["config_error"] == 4
    assert sorted(out.read_text().split()) == sorted(u for u in urls if u.endswith("serve"))
    from proxyUtil import runner

    assert runner.live_count() == 0


def test_checker_listens_on_loopback_only(tmp_path):
    from proxyUtil import xray

    url = "ss://YWVzLTEyOC1nY206cGFzc3dk@203.0.113.1:8388"
    cfg = xray.createConfig(url, 1080, listen="127.0.0.1")
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    assert xray.createConfig(url, 1080)["inbounds"][0]["listen"] == "0.0.0.0"  # client default


def test_deprecated_flags_warn_but_do_not_run(caplog, monkeypatch):
    monkeypatch.setattr(vc.cores, "resolve", lambda spec: None)
    with caplog.at_level(logging.WARNING):
        assert vc.main(["-i", "--t2kill", "1"]) == 1
    text = caplog.text
    assert "-i/--ignore is deprecated" in text and "--t2kill is deprecated" in text


WRAPPER = """
import os, sys
sys.path.insert(0, {root!r})
from proxyUtil import cores
from proxyUtil.cli import v2rayChecker
from tests.helpers import fake_spec
spec = fake_spec(int(os.environ["TARGET_PORT"]))
cores.REGISTRY["xray"] = spec
cores.resolve = lambda s: spec.binary
sys.exit(v2rayChecker.main(sys.argv[1:]))
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("extra", [[], ["--no-batch"]], ids=["batch", "per-process"])
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_signal_keeps_partial_results_and_leaves_no_orphans(tmp_path, sig, extra):
    server, port = start_http(delay=0.4)
    urls = tmp_path / "in.txt"
    urls.write_text("".join(f"ss://u{i}@h:1\n" for i in range(60)))
    out = tmp_path / "out.txt"
    script = tmp_path / "wrap.py"
    script.write_text(WRAPPER.format(root=str(ROOT)))
    proc = subprocess.Popen(
        [
            sys.executable,
            str(script),
            "-f",
            str(urls),
            "-o",
            str(out),
            "-T",
            "4",
            "-l",
            "23000",
            "--live",
            "-c",
            "xray",
            "--no-prefilter",
            "-d",
            "http://x.test/generate_204",
            *extra,
        ],
        env={**os.environ, "TARGET_PORT": str(port)},
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not (out.exists() and out.read_text()):
            time.sleep(0.1)  # --live: first find is on disk while the run continues
        assert out.read_text(), "no result streamed to disk"
        children = []
        while time.monotonic() < deadline and not children:  # a core must be alive to orphan
            children = psutil.Process(proc.pid).children(recursive=True)
            time.sleep(0.01)
        assert children
        proc.send_signal(sig)
        _, err = proc.communicate(timeout=15)
    finally:
        proc.kill()
        server.shutdown()
    lines = out.read_text().split()
    assert 0 < len(lines) < 60  # partial results kept
    assert proc.returncode == 130, err
    time.sleep(0.2)
    assert not [c for c in children if c.is_running() and c.status() != psutil.STATUS_ZOMBIE]


def test_default_probe_is_https_so_http_only_proxies_are_not_live(tmp_path, http):
    # Regression: in the free list 35 of 60 proxies answered plain-HTTP generate_204 but
    # black-holed TLS, so they were "live" yet useless. The fake target below speaks only
    # plain HTTP, like such a proxy: an https probe must call it dead.
    from tests.helpers import fake_spec

    assert vc.DEFAULT_PROBE_URL.startswith("https://")
    assert vc.build_parser().parse_args([]).domain == vc.DEFAULT_PROBE_URL
    spec = fake_spec(http)
    https = _cfg(spec, tmp_path, timeout=2)
    https.test_url = vc.DEFAULT_PROBE_URL
    assert vc.check_one("ss://a@h:1#serve", 22050, https).status == "dead"
    assert vc.check_one("ss://a@h:1#serve", 22051, _cfg(spec, tmp_path)).status == "live"
