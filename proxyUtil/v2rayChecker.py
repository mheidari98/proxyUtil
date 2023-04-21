#!/usr/bin/env python3
# Installing v2ray     
#   https://www.v2ray.com/en/welcome/install.html
#   sudo bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
import argparse
import concurrent.futures.thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
from proxyUtil import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, handlers=[ch])

CORE = "xray"
tempdir = tempfile.mkdtemp()
time2exec = 1
time2kill = 0.1
ignoreWarning = False
CTRL_C = False

def Checker(proxyList, localPort, testDomain, timeOut):
    liveProxy = []

    proxy = PROXIES.copy()  #deepcopy(PROXIES) 
    proxy['http'] = proxy['http'].format(LOCAL_PORT=localPort)
    proxy['https'] = proxy['https'].format(LOCAL_PORT=localPort)

    for url in proxyList :
        if CTRL_C :
            break
        ParseResult = urllib.parse.urlparse(url)  # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
        try:
            if ParseResult.scheme == "ss" :
                config = createShadowConfig(url, port=localPort)
            elif ParseResult.scheme == "vmess" :
                if isBase64(url[8:]):
                    jsonLoad = json.loads(base64Decode(url[8:]))
                    jsonLoad["protocol"] = "vmess"
                    config = createVmessConfig(jsonLoad, port=localPort)
                else :
                    logging.debug("Not Implemented this type of vmess url")
                    continue
            elif ParseResult.scheme == "vless" :
                config = createVmessConfig(parseVless(ParseResult), port=localPort)
            elif ParseResult.scheme == "trojan" :
                config = createTrojanConfig(ParseResult, localPort=localPort)
            else :
                logging.debug(f"Not Implemented {ParseResult.scheme}")
                continue
        except Exception as err :
            logging.error(f"{url} : {err}")
            continue

        configName = f"{tempdir}/config_{localPort}.json"
        with open(configName, "w") as f:
            json.dump(config, f)
        logging.debug(f"config file {configName} created.")

        proc = subprocess.Popen(f"{CORE} run -config {configName}", stdout=subprocess.PIPE, 
                                shell=True, preexec_fn=os.setsid) 
        time.sleep(time2exec) 

        ping = is_alive(testDomain, proxy, timeOut)
        if ping:
            if ignoreWarning :
                liveProxy.append((url, ping))
            try :
                # http://httpbin.org/ip     http://ip-api.com/json    https://api.ipify.org
                result = json.loads(requests.get('http://ip-api.com/json/', proxies=proxy, timeout = timeOut).content)
                logging.info(f"[live] ip={result['query']} @ {result['country']} ping={ping}")
                if not ignoreWarning :
                    liveProxy.append((url, ping))
            except Exception as x:
                logging.warning(f"[{'failed'}] with ping={ping}")
                pass
        else :
            logging.debug(f"[dead] Not alive")

        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # Send the signal to all the process groups
        time.sleep(time2kill)

    return liveProxy


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(description="Simple proxy checker")
    parser.add_argument("-f", "--file", help="file contain proxy")
    parser.add_argument("-d", "--domain", help="test connect domain", default='http://www.gstatic.com/generate_204')
    parser.add_argument("-t", "--timeout", help="timeout in seconds, default is 3", default=3 , type=int)
    parser.add_argument("-l", "--lport", help="start local port, default is 1080", default=1080, type=int)
    parser.add_argument('-v', "--verbose", help="increase output verbosity", action="store_true", default=False)
    parser.add_argument('-vv', '--debug', help="debug log", action='store_true', default=False)
    parser.add_argument('-T', '--threads', help="threads number, default is 10", default=10, type=int)
    parser.add_argument('-x', '--xray', help="use xray core instead v2ray", action='store_true', default=False)
    parser.add_argument('--v2ray', help="use v2ray core", action='store_true', default=False)
    parser.add_argument('--t2exec', help="time to execute v2ray, default is 1", default=1, type=float)
    parser.add_argument('--t2kill', help="time to kill v2ray, default is 0.1", default=0.1, type=float)
    parser.add_argument('--url', help="get proxy from url")
    parser.add_argument('--free', help="get free proxy", action='store_true', default=False)
    parser.add_argument('--stdin', help="get proxy from stdin", action='store_true', default=False)
    parser.add_argument('--reuse', help="reuse last checked proxy", action='store_true', default=False)
    parser.add_argument('--ignore', help="ignore proxy with warning", action='store_true', default=False)
    parser.add_argument('-o', '--output', help="output file", default='sortedProxy.txt')
    args = parser.parse_args(argv[1:])
    
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    global CORE, time2exec, time2kill, ignoreWarning, CTRL_C
    time2exec = args.t2exec
    time2kill = args.t2kill
    ignoreWarning = args.ignore

    if args.v2ray :
        CORE = shutil.which("v2ray", path=f"./v2ray:./xray:{os.environ['PATH']}")
        if not CORE :
            logging.error("v2ray not found!")
            logging.error("you can install v2ray from https://www.v2fly.org/en_US/guide/install.html")
            download = input("do you want to download v2ray now? [y/n]").strip() in ["yes", "y"]
            if download :
                downloadZray("v2fly", "v2ray")
                CORE = shutil.which("v2ray", path=f"./v2ray:./xray:{os.environ['PATH']}")
            else:
                exit(1)
    else :
        CORE = shutil.which("xray", path=f"./v2ray:./xray:{os.environ['PATH']}")
        if not CORE :
            logging.error("xray not found!")
            logging.error("you can install xray from https://github.com/XTLS/Xray-core#installation")
            download = input("do you want to download xray now? [y/n]").strip() in ["yes", "y"]
            if download :
                downloadZray("XTLS", "xray")
                CORE = shutil.which("xray", path=f"./v2ray:./xray:{os.environ['PATH']}")
            else:
                exit(1)

    logging.info(f"using {CORE} core")
    
    lines = set()
    if args.file and os.path.isfile(args.file):
        with open(args.file, 'r', encoding='UTF-8') as file:
            lines.update( parseContent(file.read().strip()) )
            logging.info(f"got {len(lines)} from reading proxy from file")

    if args.reuse and os.path.isfile(args.output):
        with open(args.output, 'r', encoding='UTF-8') as f:
            lines.update( parseContent(f.read().strip()) )

    if args.url :
        lines.update( ScrapURL(args.url) )

    if args.free :
        lines.update( ScrapURL('https://raw.githubusercontent.com/freefq/free/master/v2') )

    if args.stdin :
        lines.update( parseContent(sys.stdin.read()) )
    
    lines = list(lines)
    logging.info(f"We have {len(lines)} proxy to check")
    
    if not lines:
        logging.error("No proxy to check")
        return
    
    N = min(args.threads, len(lines))
    
    openPort = []
    port = args.lport
    while len(openPort)<N :
        if not is_port_in_use(port):
            openPort.append(port)
        port+=1
    
    with ThreadPoolExecutor(max_workers=N) as executor:
        futures = [
            executor.submit(Checker, proxyList, localPort, args.domain, args.timeout) 
                    for proxyList, localPort in zip(split2Npart(lines, N), openPort)
            ]
        try:
            for future in as_completed(futures):
                logging.debug("thread done!")
        except KeyboardInterrupt:
            CTRL_C = True
            logging.debug("CTRL+C pressed")

    liveProxy = []
    for future in as_completed(futures):
        liveProxy.extend( future.result() )

    liveProxy.sort(key=lambda x: x[1])
    with open(args.output, 'w') as f:
        for ss_url in liveProxy:
            f.write(f"{ss_url[0]}\n")

    shutil.rmtree(tempdir)


if __name__ == '__main__':
    main()

