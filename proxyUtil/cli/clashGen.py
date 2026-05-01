#!/usr/bin/env python3
import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import requests
from ruamel.yaml import YAML

from proxyUtil._common import add_source_args, add_version_arg, collect_proxies
from proxyUtil.cli.shadowChecker import FREE_SS_URL
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.os_glue import installDocker
from proxyUtil.xray import CLASH_SAMPLE_PATH

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
            if "subconverter" in requests.get("http://localhost:25500/version").text:
                return
        except Exception:
            pass
        time.sleep(1)
    sys.exit("subconverter start failed")


def _run(cmd):
    logging.debug(f"run {cmd}")
    p = subprocess.run(cmd, shell=True, capture_output=True)
    if p.returncode:
        logging.error(f"run {cmd} failed")
        logging.error(p.stderr.decode())
    return p.returncode, p.stdout.decode(), p.stderr.decode()


_BEHAVIOR_PREFIX = {"classical": "", "domain": "DOMAIN,", "ipcidr": "IP-CIDR,"}


def _get_rule_set(yaml_safe, behavior, url, policy="DIRECT"):
    try:
        res = requests.get(url)
    except Exception:
        logging.error(f"get {url} failed")
        return []
    if res.status_code != 200:
        logging.error(f"get {url} failed")
        return []
    if (prefix := _BEHAVIOR_PREFIX.get(behavior)) is None:
        logging.error(f"unknown behavior {behavior}")
        return []
    rules = yaml_safe.load(res.text)["payload"]
    logging.info(f"got {len(rules)} rules from {url}")
    return [f"{prefix}{s},{policy}" for s in rules]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple Clash Config Generator")
    add_version_arg(parser)
    add_source_args(parser, with_reuse=False)
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

    lines = collect_proxies(args, free_url=FREE_SS_URL)
    logging.info(f"We have {len(lines)} proxy")

    if not lines:
        logging.error("No proxy to check")
        parser.print_help(sys.stderr)
        return 1

    installDocker()

    with Path(CLASH_SAMPLE_PATH).open() as f:
        myclash = yaml_rt.load(f)

    if not args.dns:
        myclash.pop("dns", None)

    if args.premium:
        myclash["rule-providers"] = {
            name: {
                "type": "http",
                "behavior": behavior,
                "url": url,
                "path": f"./ruleset/{name}.yaml",
                "interval": 86400,
            }
            for name, behavior, url in DIRECT_RULE_SET + REJECT_RULE_SET
        }
        myclash["rules"] = [
            *(f"RULE-SET,{rs[0]},DIRECT" for rs in DIRECT_RULE_SET),
            *(f"RULE-SET,{rs[0]},REJECT" for rs in REJECT_RULE_SET),
            "MATCH,🔆 LIST",
        ]
    elif args.rule:
        myclash.pop("rule-providers", None)
        rules = [
            rule
            for ruleset, policy in ((DIRECT_RULE_SET, "DIRECT"), (REJECT_RULE_SET, "REJECT"))
            for _name, behavior, url in ruleset
            for rule in _get_rule_set(yaml_safe, behavior, url, policy)
        ]
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
    for i in range(1, 5):
        myclash["proxy-groups"][i]["proxies"] = proxyNames

    with Path(args.output).open("w") as f:
        yaml_rt.dump(myclash, f)
        logging.info(f"clash config saved to {args.output}")

    _run(STOP_SUBCONVERTER)
    logging.info("subconverter stopped")


if __name__ == "__main__":
    main()
