#!/usr/bin/env python3
# Cloudflare Python SDK v4+ (https://github.com/cloudflare/cloudflare-python)
# API tokens: https://dash.cloudflare.com/profile/api-tokens
# Cannot use this API for domains with .cf, .ga, .gq, .ml, or .tk TLDs.
import argparse
import os
import re
import sys

from cloudflare import APIError, Cloudflare
from rich.console import Console
from rich.table import Table

from proxyUtil._common import add_version_arg
from proxyUtil.dnsUtil import isIPv4

console = Console()


def _verbose_table(columns, style_map=None):
    style_map = style_map or {}
    t = Table(
        show_lines=True,
        show_header=True,
        header_style="bold magenta",
        row_styles=["dim", ""],
        highlight=True,
    )
    for col in columns:
        t.add_column(col, style=style_map.get(col, "cyan"), no_wrap=(col == "Name"))
    return t


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple Cloudflare DNS Recorder")
    add_version_arg(parser)
    parser.add_argument(
        "email", help="Cloudflare account email (use 'token' if using API token only)"
    )
    parser.add_argument("token", help="Cloudflare API token (preferred) or Global API Key")
    parser.add_argument("domain", help="Zone (root domain) to record under")
    parser.add_argument("subdomain", help="Subdomain to record (relative to domain)")
    parser.add_argument("-f", "--file", help="File containing the IP(s) to record")
    parser.add_argument("--stdin", help="Read the IP(s) from stdin", action="store_true")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    args = parser.parse_args(argv)

    if args.stdin:
        raw = sys.stdin.read()
    elif args.file and os.path.isfile(args.file):
        with open(args.file, encoding="UTF-8") as f:
            raw = f.read()
    else:
        raw = input("IP(s): ")

    IPs = [ip.strip() for ip in raw.split() if isIPv4(ip.strip())]
    if not IPs:
        console.print("No valid IP(s) found", style="bold red")
        return 1

    # Use API token when "email" is the literal string "token", else email + global API key.
    if args.email.lower() == "token":
        cf = Cloudflare(api_token=args.token)
    else:
        cf = Cloudflare(api_email=args.email, api_key=args.token)

    try:
        zones = list(cf.zones.list(name=args.domain))
    except APIError as e:
        console.print(f"/zones - api call failed: {e}", style="bold red")
        return 1
    if not zones:
        console.print(f"zone {args.domain!r} not found", style="bold red")
        return 1
    zone = zones[0]
    zone_id = zone.id
    zone_name = zone.name
    zone_type = getattr(zone, "type", "")
    zone_plan = getattr(getattr(zone, "plan", None), "name", "")

    ssl_status = ipv6_status = ""
    try:
        ssl_status = cf.zones.settings.get(setting_id="ssl", zone_id=zone_id).value
        ipv6_status = cf.zones.settings.get(setting_id="ipv6", zone_id=zone_id).value
    except APIError as e:
        console.print(f"/zones/settings - api call failed: {e}", style="bold yellow")

    if args.verbose:
        zt = _verbose_table(
            ["Name", "Type", "Plan", "ID"],
            {"Name": "cyan", "Type": "green", "Plan": "blue", "ID": "magenta"},
        )
        zt.add_row(zone_name, zone_type, zone_plan, zone_id)
        console.print(zt)

        st = _verbose_table(["SSL", "IPv6"], {"SSL": "cyan", "IPv6": "green"})
        st.add_row(str(ssl_status), str(ipv6_status))
        console.print(st)

    rt = _verbose_table(
        ["Name", "Type", "Value", "TTL", "ID"],
        {"Name": "cyan", "Type": "green", "Value": "blue", "TTL": "magenta", "ID": "yellow"},
    )

    try:
        dns_records = list(cf.dns.records.list(zone_id=zone_id))
    except APIError as e:
        console.print(f"/zones/dns_records - api call failed: {e}", style="bold red")
        return 1

    suffix_re = re.compile(re.escape(zone_name) + r"$")
    dns_records.sort(key=lambda r: suffix_re.sub("", r.name) + "_" + r.type)

    target_fqdn = f"{args.subdomain}.{args.domain}"
    for r in dns_records:
        if r.name == target_fqdn and r.type == "A":
            if r.content in IPs:
                IPs.remove(r.content)
                console.print(f"Found {r.name} {r.type} {r.content}", style="bold green")
                if args.verbose:
                    rt.add_row(r.name, r.type, r.content, str(r.ttl), r.id)
            else:
                try:
                    cf.dns.records.delete(r.id, zone_id=zone_id)
                    console.print(f"Deleted {r.name} {r.type} {r.content}", style="bold red")
                except APIError as e:
                    console.print(f"delete {r.id} failed: {e}", style="bold red")

    for ip in IPs:
        try:
            new = cf.dns.records.create(
                zone_id=zone_id,
                type="A",
                name=args.subdomain,
                content=ip,
                ttl=1,
                proxied=False,
            )
        except APIError as e:
            console.print(f"create {ip} failed: {e}", style="bold red")
            continue
        console.print(f"Added {new.name} {new.type} {new.content}", style="bold green")
        if args.verbose:
            rt.add_row(new.name, new.type, new.content, str(new.ttl), new.id)

    if args.verbose:
        console.print(rt)


if __name__ == "__main__":
    main()
