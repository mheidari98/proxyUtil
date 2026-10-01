"""Core process lifecycle: spawn, wait until the SOCKS port is up, always reap.

Every process is registered so a signal handler (or ``atexit``) can kill whatever is
still running — a checker must never leave open proxies behind.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time

__all__ = [
    "CoreExited",
    "CoreNotReady",
    "CoreProcess",
    "kill_all",
    "live_count",
]

_registry: set[CoreProcess] = set()
_registry_lock = threading.Lock()
_POLL_INTERVAL = 0.005
_STDERR_TAIL = 300


class CoreExited(RuntimeError):
    """The core died before its port opened (bad config, unsupported cipher, ...)."""


class CoreNotReady(TimeoutError):
    """The core stayed alive but never opened its port within the wait budget."""


class CoreProcess:
    """One core process bound to one local SOCKS port. Use as a context manager."""

    def __init__(
        self,
        argv: list[str],
        port: int,
        *,
        host: str = "127.0.0.1",
        extra_ports: tuple[int, ...] = (),
    ):
        self.argv = argv
        self.port = port
        self.ports = (port, *extra_ports)  # a batch core serves several; all must be up
        self.host = host
        self.proc: subprocess.Popen | None = None
        self._stderr = None

    def __enter__(self) -> CoreProcess:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        self._stderr = tempfile.TemporaryFile()  # noqa: SIM115 - closed in stop()
        kwargs = {} if os.name == "nt" else {"start_new_session": True}
        try:
            self.proc = subprocess.Popen(
                self.argv, stdout=subprocess.DEVNULL, stderr=self._stderr, **kwargs
            )
        except BaseException:
            self._stderr.close()
            raise
        with _registry_lock:
            _registry.add(self)

    def stderr_tail(self) -> str:
        if self._stderr is None or self._stderr.closed:
            return ""
        self._stderr.seek(0)
        text = self._stderr.read().decode("utf-8", errors="replace").strip()
        return text.splitlines()[-1][-_STDERR_TAIL:] if text else ""

    def wait_ready(self, timeout: float) -> float:
        """Poll until every port accepts a connection; return seconds waited.

        Cores do not open their inbounds in config order, so a batch is only ready
        when *all* of its ports are."""
        assert self.proc is not None
        started = time.monotonic()
        pending = list(self.ports)
        while True:
            if (code := self.proc.poll()) is not None:
                detail = self.stderr_tail() or "no output"
                raise CoreExited(f"core exited with {code}: {detail}")
            pending = [p for p in pending if not self._is_open(p)]
            if not pending:
                return time.monotonic() - started
            if time.monotonic() - started > timeout:
                raise CoreNotReady(f"port {pending[0]} not open after {timeout:g}s")
            time.sleep(_POLL_INTERVAL)

    def _is_open(self, port: int) -> bool:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((self.host, port)) == 0

    def stop(self, grace: float = 1.0) -> None:
        proc, self.proc = self.proc, None
        if proc is not None:
            _terminate(proc, grace)
        with _registry_lock:
            _registry.discard(self)
        if self._stderr is not None:
            self._stderr.close()


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        if os.name == "nt":
            proc.terminate() if sig == signal.SIGTERM else proc.kill()
        else:
            os.killpg(proc.pid, sig)


def _terminate(proc: subprocess.Popen, grace: float) -> None:
    """SIGTERM the process group, escalate to SIGKILL, and reap (no zombies)."""
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(grace)
    except subprocess.TimeoutExpired:
        _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(grace)


def kill_all() -> None:
    """Kill every still-registered core. Safe to call from signal handlers and ``atexit``."""
    with _registry_lock:
        procs = list(_registry)
    for core in procs:
        if core.proc is not None:
            _signal_group(core.proc, getattr(signal, "SIGKILL", signal.SIGTERM))


def live_count() -> int:
    with _registry_lock:
        return len(_registry)


atexit.register(kill_all)
