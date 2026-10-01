"""Stand-in for xray/sing-box in tests. Usage: ``fake_core.py <config.json>``.

Config: ``{port, mode, target}`` or a batch ``{entries: [{port, mode, target}, ...]}``.
``--check`` only validates (exit 1 if any entry is mode ``exit``), like ``xray -test``.
  serve - SOCKS5 server that ignores the requested destination and tunnels every
          connection to ``target`` (a local test HTTP server)
  exit  - print an error to stderr and exit 1 (like an unsupported cipher)
  hang  - stay alive but never open that port
"""

import json
import socket
import socketserver
import sys
import threading
import time


def _pipe(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _read(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


def make_handler(target):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            c = self.request
            c.settimeout(10)
            _ver, nmethods = _read(c, 2)
            _read(c, nmethods)
            c.sendall(b"\x05\x00")
            _ver, _cmd, _rsv, atyp = _read(c, 4)
            if atyp == 1:
                _read(c, 4)
            elif atyp == 3:
                _read(c, _read(c, 1)[0])
            else:
                _read(c, 16)
            _read(c, 2)
            upstream = socket.create_connection(tuple(target), timeout=10)
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            c.settimeout(None)
            t = threading.Thread(target=_pipe, args=(upstream, c), daemon=True)
            t.start()
            _pipe(c, upstream)

    return Handler


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _entries(cfg):
    if "entries" in cfg:
        return cfg["entries"]
    return [{"port": cfg["port"], "mode": cfg.get("mode", "serve"), "target": cfg["target"]}]


def main():
    args = sys.argv[1:]
    check = "--check" in args
    entries = _entries(json.load(open(args[-1])))
    if any(e["mode"] == "exit" for e in entries):
        print("infra/conf: unknown cipher method: aes-256-cfb", file=sys.stderr)
        sys.exit(1)
    if check:
        return
    servers = []
    for e in entries:
        if e["mode"] == "serve":
            srv = Server(("127.0.0.1", e["port"]), make_handler(e["target"]))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers.append(srv)
    time.sleep(600)


if __name__ == "__main__":
    main()
