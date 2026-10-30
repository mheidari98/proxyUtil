"""Shared offline test scaffolding: a local HTTP target and a fake core spec."""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proxyUtil.cores import CoreSpec

FAKE_CORE = str(Path(__file__).parent / "fixtures" / "fake_core.py")


class _Handler(BaseHTTPRequestHandler):
    delay = 0.0

    def _reply(self):
        time.sleep(type(self).delay)
        status = {"/generate_204": 204, "/ok": 200, "/forbidden": 403}.get(self.path, 404)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET = _reply

    def log_message(self, *args):
        pass


def start_http(delay: float = 0.0) -> tuple[ThreadingHTTPServer, int]:
    handler = type("H", (_Handler,), {"delay": delay})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def fake_spec(target_port: int, *, mode="serve", schemes=("ss", "vless")) -> CoreSpec:
    """CoreSpec whose "core" is fake_core.py; URL fragment ``#exit``/``#hang`` picks a mode."""

    def write_config(url, port, path, *, listen="127.0.0.1"):
        chosen = url.rsplit("#", 1)[-1] if "#" in url else mode
        chosen = chosen if chosen in {"serve", "exit", "hang"} else mode
        cfg = Path(path) / f"fake_{port}.json"
        cfg.write_text(
            json.dumps({"port": port, "mode": chosen, "target": ["127.0.0.1", target_port]})
        )
        return str(cfg)

    def build_batch(items, *, listen="127.0.0.1"):
        entries = []
        for url, port in items:
            chosen = url.rsplit("#", 1)[-1] if "#" in url else mode
            chosen = chosen if chosen in {"serve", "exit", "hang"} else mode
            entries.append({"port": port, "mode": chosen, "target": ["127.0.0.1", target_port]})
        return {"entries": entries}, list(range(len(items)))

    return CoreSpec(
        name="fake",
        binary=sys.executable,
        schemes=frozenset(schemes),
        write_config=write_config,
        run_argv=lambda binary, config: [binary, FAKE_CORE, config],
        build_batch=build_batch,
        check_argv=lambda binary, config: [binary, FAKE_CORE, "--check", config],
    )
