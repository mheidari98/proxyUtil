#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path

from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.parsers import parseContent
from proxyUtil.schemes import ss_scheme
from proxyUtil.shadowsocks import ssURI2sslocal


def main(argv=None):
    parser = argparse.ArgumentParser(description="shadowsocks URI to ss-local command")
    add_version_arg(parser)
    parser.add_argument("-i", "--input", help="shadowsocks URI")
    parser.add_argument("-f", "--file", help="file contain shadowsocks URIs")
    parser.add_argument("-o", "--output", help="ss-local command(s) output file")
    parser.add_argument("-l", "--lport", help="local port, default is 1080", default=1080, type=int)
    args = parser.parse_args(argv)

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logging.basicConfig(level=logging.ERROR, handlers=[ch])

    results = []
    if args.input:
        results.append(ssURI2sslocal(args.input, args.lport))
    if args.file:
        lines = parseContent(Path(args.file).read_text().strip(), [ss_scheme])
        results.extend(ssURI2sslocal(line.rstrip(), args.lport) for line in lines)

    output = "\n".join(results)
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
