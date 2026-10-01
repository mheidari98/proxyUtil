"""CoreProcess lifecycle against the fake core."""

import json
import sys

import pytest

from proxyUtil import runner
from proxyUtil._common import find_free_ports
from proxyUtil.runner import CoreExited, CoreNotReady, CoreProcess
from tests.helpers import FAKE_CORE


def _core(tmp_path, mode, target_port=9) -> CoreProcess:
    (port,) = find_free_ports(30000, 1)
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"port": port, "mode": mode, "target": ["127.0.0.1", target_port]}))
    return CoreProcess([sys.executable, FAKE_CORE, str(cfg)], port)


def test_ready_then_stop_reaps_and_unregisters(tmp_path):
    core = _core(tmp_path, "serve")
    with core:
        assert runner.live_count() == 1
        assert core.wait_ready(5) < 5
        proc = core.proc
    assert proc.poll() is not None  # reaped, not a zombie
    assert runner.live_count() == 0


def test_crash_before_ready_raises_with_stderr(tmp_path):
    with _core(tmp_path, "exit") as core, pytest.raises(CoreExited, match="unknown cipher"):
        core.wait_ready(5)


def test_never_binding_core_times_out(tmp_path):
    with _core(tmp_path, "hang") as core, pytest.raises(CoreNotReady):
        core.wait_ready(0.3)


def test_kill_all_stops_registered_cores(tmp_path):
    cores_ = [_core(tmp_path, "hang") for _ in range(2)]
    for c in cores_:
        c.start()
    procs = [c.proc for c in cores_]
    runner.kill_all()
    for p in procs:
        p.wait(5)
        assert p.poll() is not None
    for c in cores_:
        c.stop()
    assert runner.live_count() == 0
