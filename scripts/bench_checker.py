"""Benchmark v2rayChecker across cores: time, mem, live count.

Usage: uv run python scripts/bench_checker.py INPUT_FILE [-n N] [--cores xray sing-box]

Spawns v2rayChecker once per core. Uses psutil to walk the process tree at a
fixed interval and aggregate RSS / CPU% across the driver and every spawned
core child. Writes per-core JSON + a summary table.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import psutil

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"  # output dir (gitignored)
INPUT = ROOT / "tmp" / "all"  # overridden by the INPUT_FILE argument
SAMPLE_INTERVAL = 0.5
CORES = ("xray", "v2ray", "sing-box")


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for _ in path.open("rb") if _.strip())


def scheme_breakdown(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    c: Counter[str] = Counter()
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            c[urlsplit(line).scheme or "?"] += 1
    return dict(c)


def sample_tree(parent: psutil.Process):
    """Return (rss_bytes_total, num_threads_total, child_count, alive)."""
    try:
        procs = [parent, *parent.children(recursive=True)]
    except psutil.NoSuchProcess:
        return 0, 0, 0, False
    rss = 0
    threads = 0
    n = 0
    alive = False
    for p in procs:
        try:
            with p.oneshot():
                rss += p.memory_info().rss
                threads += p.num_threads()
            alive = True
            n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rss, threads, n, alive


def cpu_total(parent: psutil.Process) -> float:
    """Cumulative CPU seconds (user+system) across parent + descendants."""
    try:
        procs = [parent, *parent.children(recursive=True)]
    except psutil.NoSuchProcess:
        return 0.0
    total = 0.0
    for p in procs:
        try:
            t = p.cpu_times()
            total += t.user + t.system
            if hasattr(t, "children_user"):
                total += t.children_user + t.children_system
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total


def run_one(core: str, args) -> dict:
    out_path = BENCH / f"sorted_{core}.txt"
    if out_path.exists():
        out_path.unlink()

    cmd = [
        "uv",
        "run",
        "v2rayChecker",
        "-v",
        "-c",
        core,
        "-d",
        args.domain,
        "-T",
        str(args.threads),
        "-t",
        str(args.timeout),
        "-f",
        str(INPUT),
        "-o",
        str(out_path),
    ]
    if args.number:
        cmd += ["-n", str(args.number)]

    log_path = BENCH / f"log_{core}.txt"
    log_fh = log_path.open("w")
    print(f"[{core}] launching: {' '.join(cmd)}", flush=True)

    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log_fh, stderr=subprocess.STDOUT)
    parent = psutil.Process(proc.pid)

    peak_rss = 0
    peak_children = 0
    samples: list[tuple[float, int, int]] = []  # (t, rss, child_count)

    try:
        while proc.poll() is None:
            rss, _threads, n, alive = sample_tree(parent)
            if alive:
                if rss > peak_rss:
                    peak_rss = rss
                if n > peak_children:
                    peak_children = n
                samples.append((time.monotonic() - t0, rss, n))
            time.sleep(SAMPLE_INTERVAL)
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(10)
        raise
    finally:
        log_fh.close()

    wall = time.monotonic() - t0

    rc = proc.returncode
    live = count_lines(out_path)
    schemes = scheme_breakdown(out_path)

    result = {
        "core": core,
        "wall_seconds": round(wall, 2),
        "peak_rss_mb": round(peak_rss / 1024 / 1024, 1),
        "peak_proc_count": peak_children,
        "live_proxies": live,
        "live_by_scheme": schemes,
        "exit_code": rc,
        "samples": len(samples),
        "cmd": cmd,
    }
    (BENCH / f"result_{core}.json").write_text(json.dumps(result, indent=2))
    print(f"[{core}] done: {result}", flush=True)
    return result


def main():
    global INPUT
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path, help="proxy list file (plain or base64 subscription)")
    p.add_argument("-d", "--domain", default="https://web.telegram.org")
    p.add_argument("-T", "--threads", default=200, type=int)
    p.add_argument("-t", "--timeout", default=3, type=int)
    p.add_argument("-n", "--number", type=int, help="limit number of proxies")
    p.add_argument("--cores", nargs="+", default=list(CORES), help="subset of cores to bench")
    args = p.parse_args()
    INPUT = args.input.resolve()

    BENCH.mkdir(exist_ok=True)
    if not INPUT.exists():
        sys.exit(f"input missing: {INPUT}")
    from proxyUtil.parsers import parseContent

    total_in = len(parseContent(INPUT.read_text(errors="replace")))

    results = []
    for core in args.cores:
        bin_dir = ROOT / core
        if not (bin_dir / core).exists() and not shutil.which(core):
            print(f"[{core}] binary missing under {bin_dir}; skipping", flush=True)
            continue
        results.append(run_one(core, args))

    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    summary = {
        "commit": commit,
        "input_lines": total_in,
        "domain": args.domain,
        "threads": args.threads,
        "timeout": args.timeout,
        "results": results,
    }
    (BENCH / "summary.json").write_text(json.dumps(summary, indent=2))
    print("\n=== Summary ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
