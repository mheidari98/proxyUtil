#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import tempfile
import shlex
import signal
from modules.myUtil import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CORE = "xray"
tempdir = tempfile.mkdtemp()

PROXYCHAINS = """
strict_chain
proxy_dns 
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
quiet_mode

[ProxyList]
socks5  127.0.0.1 {LOCAL_PORT}
"""

def set_proxychains(localPort):
    pchPath = os.path.expanduser('~/.proxychains/proxychains.conf')
    if os.path.exists(pchPath):
        os.system(f"cp {pchPath} {pchPath}.bak")
    with open(pchPath, "w") as f:
        f.write(PROXYCHAINS.format(LOCAL_PORT=localPort))
    logging.info("proxychains.conf updated!")


def ss_runner(ss_url, localPort):
    cmd = ssURI2sslocal(ss_url, localPort)
    logging.info(f"Running {cmd}")
    try:
        #os.execv('/bin/sh', shlex.split(cmd)) 
        p = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt")
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)  # Send the signal to all the process groups
        time.sleep(1)    # sleep 1 seconds
    except:
        logging.error(f"ss-local failed to start")
    return


def v2ray_runner(url, localPort):
    # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    ParseResult = urllib.parse.urlparse(url)  
    try:
        if ParseResult.scheme == "ss" :
            config = createShadowConfig(url, port=localPort)
        elif ParseResult.scheme == "vmess" :
            if isBase64(url[8:]):
                jsonLoad = json.loads(base64Decode(url[8:]))
                config = createVmessConfig(jsonLoad, port=localPort)
            else :
                logging.error("Not Implemented this type of vmess url")
                return
        elif ParseResult.scheme == "vless" :
            config = createVmessConfig(parseVless(ParseResult), port=localPort)
        elif ParseResult.scheme == "trojan" :
            config = createTrojanConfig(ParseResult, localPort=localPort)
        else :
            logging.error(f"Not Implemented {ParseResult.scheme}")
            return
    except Exception as err :
        logging.error(err)
        return
    #print(json.dumps(config, indent=4))
    configName = f"{tempdir}/config.json"
    with open(configName, "w") as f:
        json.dump(config, f)
    logging.debug(f"config file {configName} created.")

    cmd = f"{CORE} run -config {configName}" 
    logging.info(f"Running {cmd}")
    try:
        p = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt")
        #p.kill()
        #p.send_signal(signal.SIGINT)
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)  # Send the signal to all the process groups
        time.sleep(1)    # sleep 1 seconds
    except:
        logging.error(f"{CORE} failed to start")
    return


def main():
    parser = argparse.ArgumentParser(description="Simple proxy client for ss/v2ray/trojan")
    parser.add_argument("link", help="proxy link")
    parser.add_argument("-l", "--lport", help="start local port, default is 1080", default=1080, type=int)
    parser.add_argument("--v2ray", help="use v2ray-core", action="store_true")
    parser.add_argument("--ss", help="use shadowsocks-libev", action="store_true")
    parser.add_argument("--proxychains", help="set proxychains", action="store_true")
    args = parser.parse_args()

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

    if args.ss and args.link.startswith("ss://"):
        if not is_tool('ss-local'):
            logging.error("ss-local not found, please install shadowsocks client first")
            logging.error("\thttps://github.com/shadowsocks/shadowsocks-libev")
            return
        ss_runner(args.link, args.lport)
        return

    elif args.v2ray or (not is_tool('xray')) :
        if not is_tool('v2ray'):
            logging.error("v2ray not found, please install v2ray-core first")
            logging.error("\thttps://github.com/v2fly/v2ray-core")
            return
        global CORE
        CORE = "v2ray"
    v2ray_runner(args.link, args.lport)


if __name__ == '__main__':
    main()
    shutil.rmtree(tempdir)

