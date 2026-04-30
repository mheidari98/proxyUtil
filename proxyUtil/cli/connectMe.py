#!/usr/bin/env python3
import argparse
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time

from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.myUtil import (
    createConfig,
    is_port_in_use,
    is_tool,
    set_proxychains,
    set_system_proxy,
    ssURI2sslocal,
)
from proxyUtil.network import downloadZray


def _ss_runner(ss_url, localPort):
    cmd = ssURI2sslocal(ss_url, localPort)
    logging.info(f"Running {cmd}")
    p = None
    try:
        p = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt")
        if p is not None:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            time.sleep(1)
    except Exception:
        logging.error("ss-local failed to start")


def _v2ray_runner(core, url, localPort, tempdir):
    configName = createConfig(url, localPort, tempdir)
    if configName is None:
        return

    cmd = f"{core} run -config {configName}"
    logging.info(f"Running {cmd}")
    p = None
    try:
        p = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt")
        if p is not None:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            time.sleep(1)
    except Exception:
        logging.error(f"{core} failed to start")


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
        help="select core from [v2ray, xray, shadowsocks-libev]",
        choices=["xray", "v2ray", "ss", "wxray"],
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
            return

        if args.proxychains:
            if not is_tool("proxychains"):
                logging.error("proxychains not found, please install it first")
                logging.error("\tsudo apt install proxychains")
                return
            set_proxychains(args.lport)

        logging.info(f"Starting proxy client on port {args.lport} with PID {os.getpid()}")

        if args.system:
            set_system_proxy(proxyHost="127.0.0.1", proxyPort=args.lport, enable=True)

        if args.core == "ss" and args.link.startswith("ss://"):
            if not is_tool("ss-local"):
                logging.error("ss-local not found, please install shadowsocks client first")
                logging.error("\thttps://github.com/shadowsocks/shadowsocks-libev")
                return
            _ss_runner(args.link, args.lport)
        else:
            os.environ["PATH"] += os.pathsep + os.path.join(".", "xray")
            os.environ["PATH"] += os.pathsep + os.path.join(".", "v2ray")

            core = shutil.which(args.core)
            if not core:
                logging.error(f"{args.core} not found!")
                if args.core == "v2ray":
                    logging.error("install v2ray: https://www.v2fly.org/en_US/guide/install.html")
                else:
                    logging.error("install xray: https://github.com/XTLS/Xray-core#installation")
                if input("do you want to download it now? [y/n]").strip() in ["yes", "y"]:
                    if args.core == "v2ray":
                        downloadZray("v2fly", "v2ray")
                    else:
                        downloadZray("XTLS", "xray")
                    core = shutil.which(args.core)
                else:
                    return 1

            logging.info(f"using {core} core")
            _v2ray_runner(core, args.link, args.lport, tempdir)

        if args.system:
            set_system_proxy(enable=False)
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


if __name__ == "__main__":
    main()
