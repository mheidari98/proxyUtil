#!/usr/bin/env python3
# Installing v2ray     
#   https://www.v2ray.com/en/welcome/install.html
#   sudo bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
import argparse
import concurrent.futures.thread
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from proxyUtil import *

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, handlers=[ch])

CORE = "xray"
time2exec = 1
time2kill = 0.1
ignoreWarning = False
CTRL_C = False
tempdir = tempfile.mkdtemp()
OS = get_OS()

def Checker(proxyList, localPort, testDomain, timeOut):
    liveProxy = []

    proxy = PROXIES.copy()  #deepcopy(PROXIES) 
    proxy['http'] = proxy['http'].format(LOCAL_PORT=localPort)
    proxy['https'] = proxy['https'].format(LOCAL_PORT=localPort)

    runner = winRunCore if OS == "windows" else unixRunCore
    killer = winKillCore if OS == "windows" else unixKillCore

    for url in proxyList :
        if CTRL_C :
            break
        
        configName = createConfig(url, localPort, tempdir)
        if configName is None :
            continue
        
        proc = runner(CORE, configName)
        time.sleep(time2exec) 

        ping = is_alive(testDomain, proxy, timeOut)
        if ping:
            if not ignoreWarning :
                logging.warning(f"[{'live'}] with ping={ping}")
                liveProxy.append((url, ping))
            else:
                ip, country = getIPnCountry(proxy, timeOut)
                if ip is None :
                    logging.warning(f"[{'live'}] with ping={ping}")
                else :
                    logging.info(f"[live] ip={ip} @ {country} ping={ping}")
                    liveProxy.append((url, ping))
        else :
            logging.debug(f"[dead] Not alive")

        killer(proc)
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
    parser.add_argument('-n', '--number', help="number of proxy to check", type=int)
    parser.add_argument('-x', '--xray', help="use xray core instead v2ray", action='store_true', default=False)
    parser.add_argument('-c', '--core', help="select core from [v2ray, xray]", choices=["v2ray", "xray", "wxray"], default="xray")
    parser.add_argument('--t2exec', help="time to execute core, default is 1", default=1, type=float)
    parser.add_argument('--t2kill', help="time to kill core, default is 0.1", default=0.1, type=float)
    parser.add_argument('--url', help="get proxy from url")
    parser.add_argument('--free', help="get free proxy", action='store_true', default=False)
    parser.add_argument('--stdin', help="get proxy from stdin", action='store_true', default=False)
    parser.add_argument('--reuse', help="reuse last checked proxy", action='store_true', default=False)
    parser.add_argument('-i', '--ignore', help="ignore proxy with warning", action='store_false', default=True)
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

    os.environ["PATH"] += os.pathsep + os.path.join('.', 'xray')
    os.environ["PATH"] += os.pathsep + os.path.join('.', 'v2ray')

    CORE = shutil.which(args.core)
    if not CORE :
        logging.error(f"{args.core} not found!")
        if args.core == "v2ray" :
            logging.error("you can install v2ray from https://www.v2fly.org/en_US/guide/install.html")
        else:
            logging.error("you can install xray from https://github.com/XTLS/Xray-core#installation")
        download = input("do you want to download it now? [y/n]").strip() in ["yes", "y"]
        if download :
            if args.core == "v2ray" :
                downloadZray("v2fly", "v2ray")
            else:
                downloadZray("XTLS", "xray")
            CORE = shutil.which(args.core)
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
        lines.update( ScrapURL('https://raw.githubusercontent.com/mheidari98/.proxy/main/all') )

    if args.stdin :
        lines.update( parseContent(sys.stdin.read()) )
    
    lines = list(lines)
    if args.number :
        lines = random.sample(lines, min(args.number, len(lines)))
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
    logging.debug(f"open port: {openPort}")
    
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
            logging.info("CTRL+C pressed")

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

