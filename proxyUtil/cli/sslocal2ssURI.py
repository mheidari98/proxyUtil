#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path

from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.shadowsocks import sslocal2ssURI


def main(argv=None):
    parser = argparse.ArgumentParser(description="ss-local command to shadowsocks URI")
    add_version_arg(parser)
    parser.add_argument("-i", "--input", help="ss-local command")
    parser.add_argument("-f", "--file", help="file contain ss-local commands")
    parser.add_argument("-o", "--output", help="shadowsocks URI(s) output file")
    args = parser.parse_args(argv)

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logging.basicConfig(level=logging.ERROR, handlers=[ch])

    results = []
    if args.input:
        results.append(sslocal2ssURI(args.input))
    if args.file:
        results.extend(
            sslocal2ssURI(line.rstrip())
            for line in Path(args.file).read_text().splitlines()
            if "ss-local" in line
        )

    output = "\n".join(results)
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
