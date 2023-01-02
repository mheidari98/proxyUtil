#!/usr/bin/env python3
# https://github.com/tindy2013/subconverter
# https://v2rayse.com/en/v2ray-clash
# https://realpython.com/python-yaml
import argparse
from modules.myUtil import *

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

CLASH_SAMPLE_PATH = './modules/Clash-Template.yaml'


def checkSubConverter():
    for i in range(10):
        try:
            res = requests.get('http://localhost:25500/version').text
        except:
            time.sleep(1)
            continue
        if "subconverter" in res :
            break
    else:
        sys.exit("subconverter start failed")


def main():
    parser = argparse.ArgumentParser(description="Simple Clash Config Generator")
    parser.add_argument("-f", "--file", help="file contain ss proxy")
    parser.add_argument('--url', help="get proxy from url")
    parser.add_argument('--stdin', help="get proxy from stdin", action='store_true', default=False)
    parser.add_argument('--free', help="get free proxy", action='store_true', default=False)
    # https://github.com/Dreamacro/clash/wiki/Clash-Premium-Features
    parser.add_argument('--premium', help="use Clash Premium Features", action='store_true', default=False)
    parser.add_argument('-v', "--verbose", help="increase output verbosity", action="store_true", default=False)
    parser.add_argument('-vv', '--debug', help="debug log", action='store_true', default=False)
    parser.add_argument('-o', '--output', help="output file", default='clashConfig.yaml')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    lines = set()
    if args.file and os.path.isfile(args.file):
        with open(args.file, 'r', encoding='UTF-8') as file:
            lines.update( parseContent(file.read().strip()) )
            logging.info(f"got {len(lines)} from reading proxy from file")

    if args.url :
        lines.update( ScrapURL(args.url) )
    
    if args.free :
        lines.update( ScrapURL('https://raw.githubusercontent.com/freefq/free/master/v2') )

    if args.stdin :
        lines.update( parseContent(sys.stdin.read()) )

    lines = list(lines)
    logging.info(f"We have {len(lines)} proxy")
    
    if not lines:
        logging.error("No proxy to check")
        parser.print_help(sys.stderr)
        return
    
    installDocker()
    
    cmd = f"docker run -d --rm --name 'subconverter' -p 25500:25500 tindy2013/subconverter:latest"
    subprocess.run(cmd, shell=True, check=True)

    checkSubConverter()

    URLEncode = '|'.join( map( quote, lines) )
    res = requests.get(f"http://127.0.0.1:25500/sub?target=clash&url={URLEncode}", timeout=10)

    clashyml = yaml.safe_load(res.text)
    
    proxyNames = [proxy['name'] for proxy in clashyml['proxies']]

    with open(CLASH_SAMPLE_PATH) as f:
        #myclash = yaml.load(f, Loader=yaml.FullLoader)
        #myclash = yaml.safe_load(f)
        myclash = yaml.load(f, Loader=yaml.RoundTripLoader)

    if not args.premium:
        myclash.pop('rule-providers')
        myclash['rules'] = myclash['rules'][1:]

    myclash['proxies'] = clashyml['proxies']

    # "🔆 LIST"
    extended = ["🔥 Auto(Best ping)", "Auto-Fallback", "⚖️ load-balance hash", "⚖️ load-balance round-robin", "DIRECT", "REJECT"] 
    myclash['proxy-groups'][0]['proxies'] = extended + proxyNames

    # "🔥 Auto(Best ping)"
    myclash['proxy-groups'][1]['proxies'] = proxyNames

    # "Auto-Fallback"
    myclash['proxy-groups'][2]['proxies'] = proxyNames

    # "⚖️ load-balance hash"
    myclash['proxy-groups'][3]['proxies'] = proxyNames

    # "⚖️ load-balance round-robin"
    myclash['proxy-groups'][4]['proxies'] = proxyNames

    with open(args.output, 'w') as f:
        #yaml.dump(myclash, f, default_flow_style=False, sort_keys=False, indent=4)
        yaml.dump(myclash, f, Dumper=yaml.RoundTripDumper, allow_unicode = True, encoding = None, indent=4)

    subprocess.run("docker stop subconverter", shell=True, check=True)


if __name__ == '__main__':
    main()
