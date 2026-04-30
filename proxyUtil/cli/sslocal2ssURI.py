#!/usr/bin/env python3
import argparse
import logging

from proxyUtil._common import add_version_arg
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.myUtil import sslocal2ssURI


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
        with open(args.file) as fh:
            for line in fh:
                if "ss-local" in line:
                    results.append(sslocal2ssURI(line.rstrip()))

    outputs = "\n".join(results)
    if args.output:
        with open(args.output, "w") as f:
            f.write(outputs)
    else:
        print(outputs)


if __name__ == "__main__":
    main()
