#!/usr/bin/env python3
import argparse
import logging
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

from proxyUtil import cores
from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.os_glue import (
    is_port_in_use,
    is_tool,
    set_proxychains,
    set_system_proxy,
)
from proxyUtil.shadowsocks import ssURI2sslocal


def _spawn(argv, label):
    """Spawn `argv`, sleep until KeyboardInterrupt, then SIGTERM the process group."""
    logging.info(f"Running {' '.join(argv)}")
    p = None
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, preexec_fn=os.setsid)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt")
        if p is not None:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            time.sleep(1)
    except Exception:
        logging.error(f"{label} failed to start")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple proxy client for ss/v2ray/trojan")
    add_version_arg(parser)
    parser.add_argument("link", help="proxy link")
    parser.add_argument(
        "-l", "--lport", help="start local port, default is 1080", default=1080, type=int
    )
    parser.add_argument(
        "-c",
        "--core",
        help="core to launch ('ss' uses ss-local for ss:// links)",
        choices=(*cores.CORE_NAMES, "ss"),
        default="xray",
    )
    parser.add_argument("--proxychains", help="set proxychains", action="store_true")
    parser.add_argument("--system", help="set system proxy", action="store_true")
    args = parser.parse_args(argv)

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[ch])

    tempdir = tempfile.mkdtemp()
    try:
        if is_port_in_use(args.lport):
            logging.error(f"port {args.lport} is in use")
            return None

        if args.proxychains:
            if not is_tool("proxychains"):
                logging.error("proxychains not found, please install it first")
                logging.error("\tsudo apt install proxychains")
                return None
            set_proxychains(args.lport)

        logging.info(f"Starting proxy client on port {args.lport} with PID {os.getpid()}")

        if args.system:
            set_system_proxy(proxyHost="127.0.0.1", proxyPort=args.lport, enable=True)

        if args.core == "ss" and args.link.startswith("ss://"):
            if not is_tool("ss-local"):
                logging.error("ss-local not found, please install shadowsocks client first")
                logging.error("\thttps://github.com/shadowsocks/shadowsocks-libev")
                return None
            _spawn(shlex.split(ssURI2sslocal(args.link, args.lport)), "ss-local")
        else:
            spec = cores.get(args.core)
            binary = cores.resolve(spec)
            if not binary:
                return 1
            logging.info(f"using {spec.name} at {binary}")
            configName = spec.write_config(args.link, args.lport, tempdir)
            if configName is not None:
                _spawn(spec.run_argv(binary, configName), spec.name)

        if args.system:
            set_system_proxy(enable=False)
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)
    return None


if __name__ == "__main__":
    main()
