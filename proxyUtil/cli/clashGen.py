#!/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import sys
import time
from urllib.parse import quote

import requests
from ruamel.yaml import YAML

from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.myUtil import CLASH_SAMPLE_PATH, ScrapURL, installDocker, parseContent

# https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash
# https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash
# https://github.com/Hackl0us/SS-Rule-Snippet
# https://github.com/chiroots/iran-hosted-domains
# https://github.com/MasterKia/PersianBlocker
# https://github.com/farrokhi/adblock-iran
DIRECT_RULE_SET = [
    (
        "iran",
        "classical",
        "https://github.com/SamadiPour/iran-hosted-domains/releases/latest/download/clash_rules.yaml",
    ),
    (
        "private",
        "domain",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt",
    ),
]

REJECT_RULE_SET = [
    (
        "adblock",
        "domain",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
    ),
]

START_SUBCONVERTER = (
    "docker run -d --rm --name 'subconverter' -p 25500:25500 tindy2013/subconverter:latest"
)
STOP_SUBCONVERTER = "docker stop subconverter"


def _check_subconverter():
    for _ in range(10):
        try:
            res = requests.get("http://localhost:25500/version").text
        except Exception:
            time.sleep(1)
            continue
        if "subconverter" in res:
            break
    else:
        sys.exit("subconverter start failed")


def _run(cmd):
    logging.debug(f"run {cmd}")
    p = subprocess.run(cmd, shell=True, capture_output=True)
    if p.returncode:
        logging.error(f"run {cmd} failed")
        logging.error(p.stderr.decode())
    return p.returncode, p.stdout.decode(), p.stderr.decode()


def _get_rule_set(yaml_safe, behavior, url, policy="DIRECT"):
    try:
        res = requests.get(url)
    except Exception:
        logging.error(f"get {url} failed")
        return []
    if res.status_code != 200:
        logging.error(f"get {url} failed")
        return []
    rules = yaml_safe.load(res.text)["payload"]
    logging.info(f"got {len(rules)} rules from {url}")
    if behavior == "classical":
        return [f"{s},{policy}" for s in rules]
    if behavior == "domain":
        return [f"DOMAIN,{s},{policy}" for s in rules]
    if behavior == "ipcidr":
        return [f"IP-CIDR,{s},{policy}" for s in rules]
    logging.error(f"unknown behavior {behavior}")
    return []


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple Clash Config Generator")
    add_version_arg(parser)
    parser.add_argument("-f", "--file", help="file contain ss proxy")
    parser.add_argument("--url", help="get proxy from url")
    parser.add_argument("--stdin", help="get proxy from stdin", action="store_true")
    parser.add_argument("--free", help="get free proxy", action="store_true")
    parser.add_argument("--dns", help="use DNS server", action="store_true")
    parser.add_argument("--rule", help="use rules", action="store_true")
    parser.add_argument("--premium", help="use Clash Premium Features", action="store_true")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-vv", "--debug", help="debug log", action="store_true")
    parser.add_argument(
        "-o", "--output", help="output file (default: clashConfig.yaml)", default="clashConfig.yaml"
    )
    args = parser.parse_args(argv)

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logging.basicConfig(level=logging.WARNING, handlers=[ch])

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    yaml_rt = YAML(typ="rt")
    yaml_rt.allow_unicode = True
    yaml_rt.indent(mapping=4, sequence=4, offset=2)
    yaml_safe = YAML(typ="safe")

    lines = set()
    if args.file and os.path.isfile(args.file):
        with open(args.file, encoding="UTF-8") as fh:
            lines.update(parseContent(fh.read().strip()))
            logging.info(f"got {len(lines)} from reading proxy from file")

    if args.url:
        lines.update(ScrapURL(args.url))

    if args.free:
        lines.update(ScrapURL("https://raw.githubusercontent.com/freefq/free/master/v2"))

    if args.stdin:
        lines.update(parseContent(sys.stdin.read()))

    lines = list(lines)
    logging.info(f"We have {len(lines)} proxy")

    if not lines:
        logging.error("No proxy to check")
        parser.print_help(sys.stderr)
        return 1

    installDocker()

    with open(CLASH_SAMPLE_PATH) as f:
        myclash = yaml_rt.load(f)

    if not args.dns:
        myclash.pop("dns", None)

    if args.premium:
        rulesets = {}
        for name, behavior, url in DIRECT_RULE_SET + REJECT_RULE_SET:
            rulesets[name] = {
                "type": "http",
                "behavior": behavior,
                "url": url,
                "path": f"./ruleset/{name}.yaml",
                "interval": 86400,
            }
        myclash["rule-providers"] = rulesets
        rules = [f"RULE-SET,{rs[0]},DIRECT" for rs in DIRECT_RULE_SET]
        rules += [f"RULE-SET,{rs[0]},REJECT" for rs in REJECT_RULE_SET]
        rules.append("MATCH,🔆 LIST")
        myclash["rules"] = rules
    elif args.rule:
        myclash.pop("rule-providers", None)
        rules = []
        for _name, behavior, url in DIRECT_RULE_SET:
            rules.extend(_get_rule_set(yaml_safe, behavior, url, "DIRECT"))
        for _name, behavior, url in REJECT_RULE_SET:
            rules.extend(_get_rule_set(yaml_safe, behavior, url, "REJECT"))
        rules.append("MATCH,🔆 LIST")
        myclash["rules"] = rules
    else:
        myclash.pop("rule-providers", None)

    rc, _out, _err = _run(START_SUBCONVERTER)
    if rc != 0:
        _run(STOP_SUBCONVERTER)
        rc, out, err = _run(START_SUBCONVERTER)
        if rc != 0:
            logging.error(f"start clash failed, {out}, {err}")
            return 1

    _check_subconverter()

    URLEncode = "|".join(map(quote, lines))
    res = requests.get(f"http://127.0.0.1:25500/sub?target=clash&url={URLEncode}", timeout=10)

    clashyml = yaml_safe.load(res.text)
    proxyNames = [proxy["name"] for proxy in clashyml["proxies"]]

    myclash["proxies"] = clashyml["proxies"]

    extended = [
        "🔥 Auto(Best ping)",
        "Auto-Fallback",
        "⚖️ load-balance hash",
        "⚖️ load-balance round-robin",
        "DIRECT",
        "REJECT",
    ]
    myclash["proxy-groups"][0]["proxies"] = extended + proxyNames
    myclash["proxy-groups"][1]["proxies"] = proxyNames
    myclash["proxy-groups"][2]["proxies"] = proxyNames
    myclash["proxy-groups"][3]["proxies"] = proxyNames
    myclash["proxy-groups"][4]["proxies"] = proxyNames

    with open(args.output, "w") as f:
        yaml_rt.dump(myclash, f)
        logging.info(f"clash config saved to {args.output}")

    _run(STOP_SUBCONVERTER)
    logging.info("subconverter stopped")


if __name__ == "__main__":
    main()
