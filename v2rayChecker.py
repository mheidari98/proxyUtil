#!/usr/bin/env python3
# Installing v2ray     
#   https://www.v2ray.com/en/welcome/install.html
#   sudo bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
import argparse
import concurrent.futures
import tempfile
from modules.myUtil import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

tempdir = tempfile.mkdtemp()

def Checker(proxyList, localPort, testDomain, timeOut):
    liveProxy = []
    
    proxy = PROXIES.copy()  #deepcopy(PROXIES) 
    proxy['http'] = proxy['http'].format(LOCAL_PORT=localPort)
    proxy['https'] = proxy['https'].format(LOCAL_PORT=localPort)

    for url in proxyList :
        ParseResult = urllib.parse.urlparse(url)  # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
        if ParseResult.scheme == "ss" :
            config = createShadowConfig(url, port=localPort)
        elif ParseResult.scheme == "vmess" :
            if isBase64(url[8:]):
                jsonLoad = json.loads(base64Decode(url[8:]))
                jsonLoad["protocol"] = "vmess"
                config = createVmessConfig(jsonLoad, port=localPort)
            else :
                logging.warning("Not Implemented this type of vmess url")
                continue
        elif ParseResult.scheme == "vless" :
            config = createVmessConfig(parseVless(ParseResult), port=localPort)
        elif ParseResult.scheme == "trojan" :
            logging.info(f"trojan proxy is not supported yet :(")
        else :
            logging.warning(f"Not Implemented {ParseResult.scheme}")
            continue

        configName = f"{tempdir}/config_{localPort}.json"
        with open(configName, "w") as f:
            json.dump(config, f)
        logging.debug(f"config file {configName} created.")

        proc = subprocess.Popen(f"v2ray run -config {configName}", stdout=subprocess.PIPE, 
                                shell=True, preexec_fn=os.setsid) 
        time.sleep(0.2) 

        ping = is_alive(testDomain, proxy, timeOut)
        if ping:
            liveProxy.append((url, ping))
            try :
                # http://httpbin.org/ip     http://ip-api.com/json    https://api.ipify.org
                result = json.loads(requests.get('http://ip-api.com/json/', proxies=proxy, timeout = timeOut).content)
                logging.info(f"[live] ip={result['query']} @ {result['country']} ping={ping}")
            except Exception as x:
                logging.warning(f"[{'failed'}] with ping={ping}")
                pass
        else :
            logging.info(f"[dead] Not alive")

        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # Send the signal to all the process groups
        time.sleep(0.1)    # sleep 0.1 seconds

    return liveProxy


def main():
    parser = argparse.ArgumentParser(description="Simple proxy checker")
    parser.add_argument("-f", "--file", help="file contain proxy")
    parser.add_argument("-d", "--domain", help="test connect domain", default='https://www.google.com')
    parser.add_argument("-t", "--timeout", help="timeout in seconds, default is 3", default=3 , type=int)
    parser.add_argument("-l", "--lport", help="start local port, default is 1080", default=1080, type=int)
    parser.add_argument('-v', '--verbose', help="verbose log", action='store_true', default=False)
    parser.add_argument('-T', '--threads', help="threads number, default is 10", default=10, type=int)
    parser.add_argument('--url', help="get proxy from url")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not is_tool('v2ray'):
        logging.error("v2ray not found, please install shadowsocks client first")
        logging.error("\thttps://www.v2fly.org/en_US/guide/install.html")
        exit(1)

    lines = []
    if args.file:
        with open(args.file, 'r', encoding='UTF-8') as file:
            lines = parseContent(file.read().strip(), [vmess_scheme, vless_scheme, ss_scheme])
            logging.info(f"got {len(lines)} from reading proxy from file")

    if args.url :
        lines += ScrapURL(args.url, [vmess_scheme, vless_scheme, ss_scheme])
    
    logging.info(f"We have {len(lines)} proxy to check")
    
    if not lines:
        logging.warning("No proxy to check")
        return
    
    N = min(args.threads, len(lines))
    
    openPort = []
    port = args.lport
    while len(openPort)<N :
        if not is_port_in_use(port):
            openPort.append(port)
        port+=1
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as executor:
        results = executor.map(Checker  , split2Npart(lines, N)
                                        , openPort
                                        , itertools.repeat(args.domain, N)
                                        , itertools.repeat(args.timeout, N) )
    
    
    liveProxy = [*itertools.chain(*results)]

    liveProxy.sort(key=lambda x: x[1])
    with open('sortedProxy.txt', 'w') as f:
        for ss_url in liveProxy:
            f.write(f"{ss_url[0]}\n")


if __name__ == '__main__':
    main()
    shutil.rmtree(tempdir)
