#!/usr/bin/env python3
# Installing shadowsocks client     
#   https://github.com/shadowsocks/shadowsocks-libev
#   https://www.linuxbabe.com/desktop-linux/how-to-install-and-use-shadowsocks-command-line-client
#   sudo pip install shadowsocks
import argparse
import concurrent.futures
import tempfile
from modules.myUtil import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

tempdir = tempfile.mkdtemp()

def Checker(shadowList, localPort, testDomain, timeOut):
    liveProxy = []
    
    proxy = PROXIES.copy()  #deepcopy(PROXIES) 
    proxy['http'] = proxy['http'].format(LOCAL_PORT=localPort)
    proxy['https'] = proxy['https'].format(LOCAL_PORT=localPort)
    
    pidPath = f"{tempdir}/ss.pid.{localPort}"
    
    for ss_url in shadowList :
        server, server_port, method, password = parse_ss(ss_url)

        if not isValidIP(server) and not getIP(server):
            continue

        #writeConfig2json(server, server_port, method, password, local_port=1080, configFile='{tempdir}/CONFIG.json.{localPort}')
        #cmd = f"ss-local -c {tempdir}/CONFIG.json.{localPort} -f {pidPath}"
        cmd = f"ss-local -s {server} -p {server_port} -l {localPort} -m {method} -k '{password}' -f {pidPath}"
        os.system(cmd)
        time.sleep(0.2) 

        ping = is_alive(testDomain, proxy, timeOut)
        if ping:
            liveProxy.append((ss_url, ping))
            try :
                # http://httpbin.org/ip     http://ip-api.com/json    https://api.ipify.org
                result = json.loads(requests.get('http://ip-api.com/json/', proxies=proxy, timeout = timeOut).content)
                logging.info(f"[live] ip={result['query']} @ {result['country']} ping={ping}")
            except Exception as x:
                logging.warning(f"[{'failed'}] ip={server} with ping={ping}")
                pass
        else :
            logging.info(f"[dead] ip={server}")

        os.system(f"if ps -p $(cat {pidPath}) > /dev/null 2>&1 ;then kill -9 $(cat {pidPath}); fi")
        time.sleep(0.3)    # sleep 0.3 seconds

    return liveProxy


def main():
    parser = argparse.ArgumentParser(description="Simple shadowsocks proxy checker")
    parser.add_argument("-f", "--file", help="file contain ss proxy")
    parser.add_argument("-d", "--domain", help="test connect domain", default='https://www.google.com')
    parser.add_argument("-t", "--timeout", help="timeout in seconds, default is 3", default=3 , type=int)
    parser.add_argument("-l", "--lport", help="start local port, default is 1080", default=1080, type=int)
    parser.add_argument('-v', '--verbose', help="verbose log", action='store_true', default=False)
    parser.add_argument('-T', '--threads', help="threads number, default is 10", default=10, type=int)
    parser.add_argument('--url', help="get proxy from url")
    parser.add_argument('--free', help="get free proxy", action='store_true', default=False)
    parser.add_argument('--stdin', help="get proxy from stdin", action='store_true', default=False)
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not is_tool('ss-local'):
        logging.error("ss-local not found, please install shadowsocks client first")
        logging.error("\thttps://github.com/shadowsocks/shadowsocks-libev")
        exit(1)
    
    killProcess('ss-local') # init system

    lines = []
    if args.file:
        with open(args.file, 'r', encoding='UTF-8') as file:
            lines = parseContent(file.read().strip(), [ss_scheme])
            logging.info(f"got {len(lines)} from reading proxy from file")

    if args.url :
        lines += ScrapURL(args.url, [ss_scheme])
    
    if args.free :
        lines += ScrapURL('https://raw.githubusercontent.com/freefq/free/master/v2', [ss_scheme])

    if args.stdin :
        lines += parseContent(sys.stdin.read(), [ss_scheme])

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
    with open('sortedShadow.txt', 'w') as f:
        for ss_url in liveProxy:
            f.write(f"{ss_url[0]}\n")


if __name__ == '__main__':
    main()
    shutil.rmtree(tempdir)
