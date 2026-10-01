"""End-to-end against the REAL core binaries, fully offline.

A sing-box shadowsocks *server* (one inbound per password) runs on localhost next to a
tiny HTTP target. Client configs with the right password must come out live, wrong ones
dead, through every installed core, in both batch and per-process mode. Skipped when a
binary isn't installed.
"""

import base64
import json
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from proxyUtil import cores, runner
from proxyUtil._common import find_free_ports
from proxyUtil.cli import v2rayChecker as vc
from proxyUtil.os_glue import augment_local_path
from proxyUtil.results import ResultSink
from tests.helpers import start_http

pytestmark = pytest.mark.core

augment_local_path()
SERVER = shutil.which("sing-box")
METHOD = "aes-256-gcm"
N = 12  # servers; the same N passwords are also used wrongly


def _ss_url(port, password, tag):
    userinfo = base64.urlsafe_b64encode(f"{METHOD}:{password}".encode()).decode().rstrip("=")
    return f"ss://{userinfo}@127.0.0.1:{port}#{tag}"


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    if not SERVER:
        pytest.skip("sing-box not installed (needed as the test server)")
    tmp = tmp_path_factory.mktemp("world")
    http_server, http_port = start_http()
    ports = find_free_ports(28000, N)
    cfg = {
        "log": {"level": "panic"},
        "inbounds": [
            {
                "type": "shadowsocks",
                "tag": f"s{i}",
                "listen": "127.0.0.1",
                "listen_port": port,
                "method": METHOD,
                "password": f"secret-{i}",
            }
            for i, port in enumerate(ports)
        ],
        "outbounds": [{"type": "direct"}],
    }
    path = tmp / "server.json"
    path.write_text(json.dumps(cfg))
    proc = subprocess.Popen(
        [SERVER, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    core = runner.CoreProcess([SERVER, "version"], ports[-1])  # only for wait_ready polling
    core.proc = proc
    core.wait_ready(10)
    good = [_ss_url(p, f"secret-{i}", f"good{i}") for i, p in enumerate(ports)]
    bad = [_ss_url(p, f"WRONG-{i}", f"bad{i}") for i, p in enumerate(ports)]
    yield {"tmp": tmp, "http_port": http_port, "good": good, "bad": bad}
    proc.terminate()
    proc.wait(5)
    http_server.shutdown()


def _check(world, core_name, *, batch_size):
    spec = cores.get(core_name)
    binary = shutil.which(spec.binary)
    if not binary:
        pytest.skip(f"{core_name} not installed")
    urls = world["good"] + world["bad"]
    cfg = vc.CheckerCfg(
        core=spec,
        binary=binary,
        tempdir=str(world["tmp"]),
        ready_timeout=10,
        test_url=f"http://127.0.0.1:{world['http_port']}/generate_204",
        timeout=3,
        geo=False,
        cancel=threading.Event(),
    )
    sink = ResultSink(str(world["tmp"] / f"{core_name}-{batch_size}.txt"))
    rep = vc._Reporter(len(urls), show_bar=False)
    rep.failures = failures = []
    update = rep.update
    rep.update = lambda r: (
        update(r),
        r.status != "live" and failures.append((r.url[-12:], r.status, r.error)),
    )[0]
    stopped = vc.run_check(urls, cfg, 24, 28100, sink, rep, batch_size=batch_size)
    assert stopped == "done"
    assert runner.live_count() == 0
    return set(sink.sorted_urls()), rep


@pytest.mark.parametrize("batch_size", [1, 8, 100], ids=["per-process", "batch8", "batch100"])
@pytest.mark.parametrize("core_name", ["xray", "v2ray", "sing-box"])
def test_real_core_separates_right_from_wrong_passwords(world, core_name, batch_size):
    live, rep = _check(world, core_name, batch_size=batch_size)
    missing = [f for f in rep.failures if "good" in f[0]]
    assert live == set(world["good"]), (rep.counts, missing)
    assert rep.counts["dead"] == N


def test_real_core_batch_isolates_a_config_the_core_rejects(world):
    # xray/v2ray reject aes-256-cfb at config load. The prefilter-free check_batch path
    # must still serve every valid config in the same batch.
    spec = cores.get("xray")
    binary = shutil.which("xray")
    if not binary:
        pytest.skip("xray not installed")
    cfg = vc.CheckerCfg(
        spec,
        binary,
        str(world["tmp"]),
        10,
        f"http://127.0.0.1:{world['http_port']}/generate_204",
        3,
        False,
        threading.Event(),
    )
    poisoned = _ss_url(28000, "x", "cfb").replace(
        base64.urlsafe_b64encode(f"{METHOD}:x".encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(b"aes-256-cfb:x").decode().rstrip("="),
    )
    import queue

    urls = [*world["good"][:5], poisoned]
    out = queue.Queue()
    ports = find_free_ports(28300, len(urls))
    with ThreadPoolExecutor(1) as pool:
        # bypass the cipher precheck to force the core-validation + bisect path
        spec_no_precheck = cores.CoreSpec(
            name=spec.name,
            binary=spec.binary,
            schemes=spec.schemes,
            write_config=spec.write_config,
            run_argv=spec.run_argv,
            build_batch=spec.build_batch,
            check_argv=spec.check_argv,
        )
        cfg.core = spec_no_precheck
        pool.submit(vc.check_batch, urls, ports, out, cfg).result()
    got = {}
    while not out.empty():
        r = out.get_nowait()
        got[r.url] = r
    assert got[poisoned].status == "config_error" and "cipher" in got[poisoned].error
    assert [got[u].status for u in world["good"][:5]] == ["live"] * 5


TLS_URLS = [
    "trojan://pw@203.0.113.2:443?security=tls&sni=a.example#t",
    "vless://11111111-1111-1111-1111-111111111111@203.0.113.3:443?security=tls&type=ws&path=/&sni=a.example#v",
    "vmess://"
    + base64.b64encode(
        json.dumps(
            {
                "v": "2",
                "ps": "m",
                "add": "203.0.113.4",
                "port": "443",
                "net": "ws",
                "tls": "tls",
                "id": "22222222-2222-2222-2222-222222222222",
                "aid": "0",
                "sni": "a.example",
            }
        ).encode()
    ).decode(),
]


@pytest.mark.parametrize("core_name", ["xray", "v2ray", "sing-box"])
def test_real_core_accepts_default_tls_configs(tmp_path, core_name):
    """Regression: a template-forced allowInsecure made xray reject every TLS config."""
    from proxyUtil import batch

    spec = cores.get(core_name)
    binary = shutil.which(spec.binary)
    if not binary:
        pytest.skip(f"{core_name} not installed")
    items = [(u, 28400 + i) for i, u in enumerate(TLS_URLS)]
    good, bad = batch.validate_items(spec, binary, items, str(tmp_path))
    assert not bad, bad
    assert len(good) == len(TLS_URLS)
    for url, port in items:  # and the single-config path too
        path = spec.write_config(url, port, str(tmp_path))
        ok, reason = batch.check_config(spec, binary, path)
        assert ok, (url[:20], reason)
