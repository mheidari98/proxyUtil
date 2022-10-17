#!/usr/bin/env python3
import argparse
from modules.myUtil import *


def main():
    parser = argparse.ArgumentParser(description="shadowsocks URI to ss-local command")
    parser.add_argument("-i", "--input", help="shadowsocks URI")
    parser.add_argument("-f", "--file", help="file contain shadowsocks URIs")
    parser.add_argument("-o", "--output", help="ss-local command(s) output file")
    parser.add_argument("-l", "--lport", help="local port, default is 1080", default=1080, type=int)
    args = parser.parse_args()
    
    results = []
    
    if args.input :
        server, server_port, method, password = parse_ss(args.input)
        cmd = f"ss-local -s {server} -p {server_port} -l {args.lport} -m {method} -k {password} -f ./ss.pid"
        results.append( cmd )
    
    if args.file :
        with open(args.file, 'r') as file:
            for line in file:
                if "ss://" in line :
                    server, server_port, method, password = parse_ss(line.rstrip())
                    cmd = f"ss-local -s {server} -p {server_port} -l {args.lport} -m {method} -k {password} -f ./ss.pid"
                    results.append( cmd )
    
    outputs = '\n'.join(results) 
    if args.output :
        with open(args.output, 'w') as f :
            f.write(outputs)
    else :
        print(outputs)


if __name__ == '__main__':
    main()
