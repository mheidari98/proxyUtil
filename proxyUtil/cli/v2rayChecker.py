#!/usr/bin/env python3
# Install xray:    https://github.com/XTLS/Xray-core#installation
# Install v2ray:   https://www.v2fly.org/en_US/guide/install.html
# Install sing-box: https://sing-box.sagernet.org/installation/
import argparse
import contextlib
import logging
import queue
import random
import signal
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from proxyUtil import batch, cores
from proxyUtil._common import (
    add_source_args,
    add_version_arg,
    collect_proxies,
    find_free_ports,
)
from proxyUtil.geo import flag, lookup_exit
from proxyUtil.logFormatter import CustomFormatter
from proxyUtil.parsers import dedupe_proxies, parseContent, proxy_identity, proxy_name
from proxyUtil.prefilter import prefilter
from proxyUtil.probe import probe_liveness, probe_stable, socks_proxies
from proxyUtil.results import (
    DEFAULT_RENAME,
    FORMATS,
    LIVE,
    SORTS,
    Journal,
    Result,
    ResultSink,
    format_paths,
    make_renamer,
    write_formats,
)
from proxyUtil.runner import CoreExited, CoreNotReady, CoreProcess, kill_all
from proxyUtil.speedtest import (
    SPEEDTEST_BASE,
    Transfer,
    download_urls,
    measure_download_any,
    measure_latency,
    measure_upload,
)
from proxyUtil.utils import format_geo

FREE_PROXY_URL = "https://raw.githubusercontent.com/mheidari98/.proxy/main/all"
DEFAULT_PROBE_URL = "https://www.gstatic.com/generate_204"
CHECK_LISTEN = "127.0.0.1"  # a checked config is untrusted and unauthenticated: never LAN-visible
DEFAULT_THREADS = 300
DEFAULT_THREADS_NO_BATCH = 10  # one core process each: ~35 MB apiece, so keep it modest
DEFAULT_BATCH_SIZE = 100

ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.ERROR, handlers=[ch])


@dataclass
class CheckerCfg:
    core: cores.CoreSpec
    binary: str
    tempdir: str
    ready_timeout: float
    test_url: str
    timeout: float
    geo: bool
    cancel: threading.Event
    retries: int = 0
    stable: int = 1
    verify_url: str | None = None


def _precheck(url: str, cfg: CheckerCfg) -> Result | None:
    """A Result when this core can't even try *url*, else None."""
    scheme = urlsplit(url).scheme
    if scheme not in cfg.core.schemes:
        logging.debug(f"{cfg.core.name} doesn't speak {scheme}://; skipping {url}")
        return Result(url, "unsupported", error=f"{cfg.core.name} has no {scheme}://")
    if reason := cfg.core.unsupported_reason(url):
        return Result(url, "unsupported", error=reason)
    return None


def _probe(url: str, port: int, cfg: CheckerCfg) -> Result:
    """Probe a proxy whose core is already serving *port*."""
    proxies = socks_proxies(port)
    probe = probe_liveness(cfg.test_url, proxies, cfg.timeout, retries=cfg.retries)
    probe = probe_stable(probe, cfg.test_url, proxies, cfg.timeout, cfg.stable)
    if not probe.ok:
        logging.debug(f"[dead] {probe.error}")
        return Result(url, "dead", error=probe.error)
    if cfg.verify_url:  # second stage: "live" must also mean "reaches what I need"
        check = probe_liveness(cfg.verify_url, proxies, cfg.timeout, retries=cfg.retries)
        if not check.ok:
            return Result(url, "dead", error=f"verify failed: {check.error}")
    ip = country = code = None
    # a failed lookup never costs the proxy its live status
    if cfg.geo and (info := lookup_exit(proxies, cfg.timeout)):
        ip, country, code = info.ip, info.country, info.country_code
    return Result(url, LIVE, probe.latency_ms, ip, country, code, jitter_ms=probe.jitter_ms)


def _probe_safe(url: str, port: int, cfg: CheckerCfg) -> Result:
    try:
        return _probe(url, port, cfg)
    except Exception as err:
        return Result(url, "error", error=f"{type(err).__name__}: {err}")


def check_one(url: str, port: int, cfg: CheckerCfg) -> Result:
    """One core process for one proxy. Always returns a Result."""
    if (skipped := _precheck(url, cfg)) is not None:
        return skipped

    config = cfg.core.write_config(url, port, cfg.tempdir, listen=CHECK_LISTEN)
    if config is None:
        return Result(url, "config_error", error="could not build a config")

    try:
        with CoreProcess(cfg.core.run_argv(cfg.binary, config), port) as core:
            try:
                core.wait_ready(cfg.ready_timeout)
            except CoreExited as err:  # not a dead proxy: the core refused the config
                logging.debug(f"[config_error] {url}: {err}")
                return Result(url, "config_error", error=str(err))
            except CoreNotReady as err:
                return Result(url, "error", error=str(err))
            return _probe(url, port, cfg)
    except Exception as err:
        logging.debug(f"[error] {url}: {err!r}")
        return Result(url, "error", error=f"{type(err).__name__}: {err}")


def _per_process(items: list[tuple[str, int]], emit, cfg: CheckerCfg) -> None:
    """Check *items* with one core process each, concurrently (batch-mode fallback)."""
    with ThreadPoolExecutor(max_workers=max(1, len(items))) as pool:
        for result in pool.map(lambda it: check_one(*it, cfg), items):
            emit(result)


def check_batch(urls: list[str], ports: list[int], results: queue.Queue, cfg: CheckerCfg) -> None:
    """Check many proxies through ONE core process (an inbound+outbound pair per proxy).

    The config is validated first and bisected so one bad outbound can't take the batch
    down. If the batch can't be made to run, fall back to a process per proxy. Every URL
    yields exactly one Result."""
    reported: set[str] = set()

    def emit(result: Result) -> None:
        reported.add(result.url)
        results.put(result)

    try:
        candidates = []
        for url in urls:
            if (skipped := _precheck(url, cfg)) is not None:
                emit(skipped)
            else:
                candidates.append(url)
        items = list(zip(candidates, ports, strict=False))
        if not items or cfg.cancel.is_set():
            return

        good, bad = batch.validate_items(
            cfg.core, cfg.binary, items, cfg.tempdir, listen=CHECK_LISTEN
        )
        for url, reason in bad:
            emit(Result(url, "config_error", error=reason))
        if not good:
            return

        path, built = cfg.core.write_batch(good, cfg.tempdir, listen=CHECK_LISTEN)
        if path and len(built) == len(good) and batch.check_config(cfg.core, cfg.binary, path)[0]:
            try:
                ports = tuple(port for _url, port in good)
                with CoreProcess(
                    cfg.core.run_argv(cfg.binary, path), ports[0], extra_ports=ports[1:]
                ) as core:
                    core.wait_ready(cfg.ready_timeout)
                    with ThreadPoolExecutor(max_workers=len(good)) as pool:
                        for result in pool.map(lambda it: _probe_safe(*it, cfg), good):
                            emit(result)
                return
            except (CoreExited, CoreNotReady) as err:
                logging.debug(f"batch failed to start ({err}); falling back to per-process")
        _per_process([it for it in good if it[0] not in reported], emit, cfg)
    except Exception as err:
        logging.debug(f"batch error: {err!r}")
        for url in urls:
            if url not in reported:
                emit(Result(url, "error", error=f"{type(err).__name__}: {err}"))


def _worker(
    ports: list[int], work: queue.Queue, results: queue.Queue, cfg: CheckerCfg, share: int
) -> None:
    """Own `len(ports)` local ports; pull URLs until the queue drains or we're cancelled.

    With one port this is process-per-proxy; with more, each pull is a batch. *share* is
    how many workers split the remaining queue, so the tail is spread over all of them."""
    size = len(ports)
    while not cfg.cancel.is_set():
        take = min(size, max(1, -(-work.qsize() // share)))
        chunk: list[str] = []
        while len(chunk) < take:
            try:
                chunk.append(work.get_nowait())
            except queue.Empty:
                break
        if not chunk:
            return
        if size == 1:
            results.put(check_one(chunk[0], ports[0], cfg))
        else:
            check_batch(chunk, ports, results, cfg)


class _Reporter:
    """Progress bar (TTY, quiet logging only) plus end-of-run statistics."""

    def __init__(self, total: int, show_bar: bool):
        self.total = total
        self.counts: Counter[str] = Counter()
        self.live_by_scheme: Counter[str] = Counter()
        self.seen_by_scheme: Counter[str] = Counter()
        self.unsupported_hint = 0
        self.started = time.monotonic()
        self.progress = None
        if show_bar:
            self.progress = Progress(
                TextColumn("[bold]checking"),
                BarColumn(),
                MofNCompleteColumn(),
                TextColumn("{task.fields[live]} live"),
                TimeRemainingColumn(),
                console=Console(stderr=True),
                transient=True,
            )
            self.task = self.progress.add_task("", total=total, live=0)

    def __enter__(self):
        if self.progress:
            self.progress.start()
        return self

    def __exit__(self, *exc):
        self.stop_bar()

    def stop_bar(self) -> None:
        if self.progress:
            self.progress.stop()

    def update(self, result: Result) -> None:
        scheme = urlsplit(result.url).scheme
        self.counts[result.status] += 1
        self.seen_by_scheme[scheme] += 1
        if result.status == "unsupported" and "-c sing-box" in (result.error or ""):
            self.unsupported_hint += 1
        if result.status == LIVE:
            self.live_by_scheme[scheme] += 1
            geo = (
                f" {format_geo(result.exit_ip, result.country, result.country_code)}"
                if result.exit_ip
                else ""
            )
            logging.info(f"[live] ping={result.latency_ms}ms{geo}")
        if self.progress:
            self.progress.update(self.task, advance=1, live=self.counts[LIVE])

    def summary(self, stopped: str) -> str:
        done = sum(self.counts.values())
        live = self.counts[LIVE]
        parts = [f"{live} live"] + [
            f"{n} {status}" for status, n in sorted(self.counts.items()) if status != LIVE
        ]
        note = {"interrupted": " (interrupted)", "max_live": " (stopped at --max-live)"}.get(
            stopped, ""
        )
        out = f"checked {done}/{self.total} in {time.monotonic() - self.started:.1f}s: "
        out += ", ".join(parts) + note
        if self.live_by_scheme or self.seen_by_scheme:
            by_scheme = ", ".join(
                f"{s} {self.live_by_scheme[s]}/{n}" for s, n in self.seen_by_scheme.most_common()
            )
            out += f"\nlive per scheme: {by_scheme}"
        if self.unsupported_hint:
            out += f"\n{self.unsupported_hint} configs need sing-box: re-run with -c sing-box"
        return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple proxy checker")
    add_version_arg(parser)
    parser.add_argument(
        "-d",
        "--domain",
        help="probe URL; HTTPS by default because a proxy that answers plain HTTP but "
        "black-holes TLS is useless for real traffic (default: %(default)s)",
        default=DEFAULT_PROBE_URL,
    )
    parser.add_argument(
        "-t", "--timeout", help="probe timeout in seconds, default is 3", default=3, type=float
    )
    parser.add_argument(
        "-l",
        "--lport",
        help="first local port, default is 1080 (keep it below 32768, where the OS hands out "
        "outgoing-connection ports)",
        default=1080,
        type=int,
    )
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-vv", "--debug", help="debug log", action="store_true")
    parser.add_argument(
        "-T",
        "--threads",
        help=f"concurrent probes (default {DEFAULT_THREADS}; "
        f"{DEFAULT_THREADS_NO_BATCH} with --no-batch)",
        type=int,
    )
    parser.add_argument("-n", "--number", help="number of proxy to check", type=int)
    parser.add_argument("-s", "--shuffle", help="shuffle proxies", action="store_true")
    parser.add_argument(
        "-c",
        "--core",
        help=(
            "core to validate proxies; 'auto' (default) picks sing-box, else xray, else v2ray. "
            "Use sing-box for hysteria2/tuic/hy/anytls and legacy ss ciphers."
        ),
        choices=(cores.AUTO, *cores.CORE_NAMES),
        default=cores.AUTO,
    )
    parser.add_argument(
        "--t2exec",
        help="max seconds to wait for a core to open its port, default is 5 "
        "(returns as soon as it is ready)",
        default=5,
        type=float,
    )
    parser.add_argument("--t2kill", help=argparse.SUPPRESS, type=float)  # deprecated no-op
    add_source_args(parser)
    parser.add_argument(
        "--geo",
        help="look up the exit IP/country through each live proxy (shown with -v and in "
        "--format json; implied by --rename/--country/--sort country)",
        action="store_true",
    )
    parser.add_argument("-i", "--ignore", help=argparse.SUPPRESS, action="store_true")  # deprecated
    parser.add_argument(
        "-o",
        "--output",
        help="output file, '-' for stdout (default: sortedProxy.txt)",
        default="sortedProxy.txt",
    )
    parser.add_argument(
        "--live",
        help="append each healthy proxy to the output the moment it is found "
        "(use `tail -F`; the file is rewritten sorted at the end)",
        action="store_true",
    )
    parser.add_argument(
        "--fsync",
        help="with --live, fsync after every write (crash-proof, slower)",
        action="store_true",
    )
    parser.add_argument(
        "--max-live", type=int, metavar="K", help="stop once K healthy proxies are found"
    )
    parser.add_argument(
        "--no-prefilter",
        help="skip the TCP reachability pre-filter (it drops servers that never answer, "
        "without starting a core)",
        action="store_true",
    )
    parser.add_argument(
        "--prefilter-timeout",
        help="TCP connect timeout for the pre-filter, default is 2",
        default=2,
        type=float,
    )
    parser.add_argument(
        "--prefilter-attempts",
        help="TCP connect attempts per server when it times out, default is 1",
        default=1,
        type=int,
    )
    parser.add_argument(
        "--no-batch",
        help="one core process per proxy instead of many proxies per process "
        "(slower, ~35 MB per concurrent probe)",
        action="store_true",
    )
    parser.add_argument(
        "--batch-size",
        help=f"proxies served by one core process, default is {DEFAULT_BATCH_SIZE}",
        default=DEFAULT_BATCH_SIZE,
        type=int,
    )
    parser.add_argument(
        "--retries",
        help="retry a probe that timed out up to N times (default 0; adds N x timeout to "
        "every dead proxy)",
        default=0,
        type=int,
    )
    parser.add_argument(
        "--stable",
        help="probe each live proxy K times in total; keep it if at most one probe failed "
        "(from 3 up) and report median latency and jitter (default 1)",
        default=1,
        type=int,
        metavar="K",
    )
    parser.add_argument(
        "--verify",
        metavar="URL",
        help="second-stage target a live proxy must also reach, e.g. https://web.telegram.org",
    )
    parser.add_argument(
        "--rename",
        nargs="?",
        const=DEFAULT_RENAME,
        metavar="TEMPLATE",
        help="rename each output proxy; placeholders {flag} {cc} {country} {ms} {name} "
        f"{{scheme}} (default template: '{DEFAULT_RENAME}'). Implies a country lookup.",
    )
    parser.add_argument(
        "--country",
        type=_countries,
        metavar="CC[,CC]",
        help="keep only proxies whose exit country is one of these (e.g. DE,NL). "
        "Implies a country lookup.",
    )
    parser.add_argument(
        "--sort", choices=SORTS, default="latency", help="output order (default: latency)"
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=FORMATS,
        dest="formats",
        help="output format, repeatable: txt (default, the -o file), json (<stem>.json), "
        "b64 (<stem>.b64 subscription), singbox (<stem>.singbox.json client config)",
    )
    parser.add_argument(
        "--speedtest",
        nargs="?",
        const=10,
        type=int,
        metavar="N",
        help="after checking, measure download speed (and latency/jitter) of the top N "
        "healthy proxies by latency (default N=10) and show a table",
    )
    parser.add_argument(
        "--speedtest-time", type=float, default=8.0, help="seconds cap per proxy (default 8)"
    )
    parser.add_argument(
        "--speedtest-mb", type=float, default=20.0, help="download size cap in MB (default 20)"
    )
    parser.add_argument(
        "--speedtest-upload", action="store_true", help="also measure upload (uses more data)"
    )
    parser.add_argument(
        "--speedtest-url",
        default=SPEEDTEST_BASE,
        help="server with /__down and /__up endpoints. The default (Cloudflare) falls back to "
        "OVH and cachefly for downloads when it rate-limits (HTTP 429) or times out",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip proxies already tested by an interrupted run (journal: <output>.state)",
    )
    return parser


def _countries(text: str) -> frozenset[str]:
    codes = frozenset(c.strip().upper() for c in text.split(",") if c.strip())
    if not codes or any(len(c) != 2 or not c.isalpha() for c in codes):
        raise argparse.ArgumentTypeError(f"expected ISO country codes like DE,NL, got {text!r}")
    return codes


def run_check(
    lines: list[str],
    cfg: CheckerCfg,
    threads: int,
    lport: int,
    sink: ResultSink,
    reporter: _Reporter,
    *,
    batch_size: int = 1,
    max_live: int | None = None,
    journal: Journal | None = None,
) -> str:
    """Check *lines*, streaming results into *sink*. Returns "done", "interrupted" or
    "max_live"."""
    size = max(1, min(batch_size, threads, len(lines)))
    workers = max(1, min(threads // size, -(-len(lines) // size)))
    ports = find_free_ports(lport, workers * size)
    logging.debug(f"{workers} worker(s) x {size} proxies per core process; ports {ports[:3]}...")

    work: queue.Queue[str] = queue.Queue()
    for url in lines:
        work.put(url)
    results: queue.Queue[Result] = queue.Queue()

    def take(result: Result) -> None:
        reporter.update(result)
        sink.add(result)
        if journal is not None:
            journal.record(result)

    done, stopped = 0, "done"
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [
        pool.submit(_worker, ports[i * size : (i + 1) * size], work, results, cfg, workers)
        for i in range(workers)
    ]
    try:
        while done < len(lines) and not cfg.cancel.is_set():
            try:
                result = results.get(timeout=0.25)
            except queue.Empty:
                if all(f.done() for f in futures) and results.empty():
                    break  # workers ended without producing everything
                continue
            done += 1
            take(result)
            if max_live and sink.count >= max_live:
                stopped = "max_live"
                break
    except KeyboardInterrupt:
        stopped = "interrupted"
        logging.info("CTRL+C pressed")
    finally:
        if cfg.cancel.is_set() and stopped == "done":
            stopped = "interrupted"  # SIGTERM
        if stopped != "done":
            cfg.cancel.set()
            kill_all()  # in-flight probes then fail fast instead of waiting out their timeouts
        pool.shutdown(wait=True, cancel_futures=True)
        while not results.empty():  # live finds that landed during shutdown are kept; the rest
            result = results.get_nowait()  # may be probes we killed ourselves, so not counted
            if result.status == LIVE:
                take(result)
    return stopped


@contextlib.contextmanager
def _quiet_logging(enabled: bool):
    """Keep per-config build errors and transport warnings out of a normal run: they
    scribble over the progress bar and the summary already counts them. `-v` shows them."""
    root = logging.getLogger()
    previous = root.level
    if enabled:
        root.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        root.setLevel(previous)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.ignore:
        logging.warning("-i/--ignore is deprecated and has no effect: geo is opt-in via --geo")
    if args.t2kill is not None:
        logging.warning("--t2kill is deprecated and has no effect: cores are reaped immediately")

    formats = list(dict.fromkeys(args.formats or ["txt"]))
    extra_formats = [f for f in formats if f != "txt"]
    if args.output == "-" and extra_formats:
        parser.error("--format json/b64/singbox need a file: use -o FILE, not -o -")
    if args.output != "-" and "txt" in formats:
        for fmt, path in format_paths(args.output, extra_formats).items():
            if path == Path(args.output):
                parser.error(f"-o {args.output} would be overwritten by --format {fmt}")
    if args.sort == "speed" and args.speedtest is None:
        parser.error("--sort speed needs --speedtest")

    if args.core == cores.AUTO:
        spec = cores.pick_auto() or cores.get("xray")  # none installed: offer to fetch xray
    else:
        spec = cores.get(args.core)
    binary = cores.resolve(spec)
    if not binary:
        return 1
    logging.info(f"using {spec.name} at {binary}")
    logging.info(f"{spec.name} validates: {sorted(spec.schemes)}")

    lines = collect_proxies(args, free_url=FREE_PROXY_URL)
    collected = len(lines)
    lines = dedupe_proxies(lines)
    if len(lines) < collected:
        logging.info(f"dropped {collected - len(lines)} duplicates that differ only by name")

    lines = _order(lines, args)
    if args.number:
        lines = lines[: args.number]

    journal = None
    restored: list[Result] = []
    if args.output != "-":
        journal = Journal(f"{args.output}.state")
        if args.resume:
            tested, restored = journal.load()
            before = len(lines)
            lines = [u for u in lines if proxy_identity(u) not in tested]
            logging.info(
                f"resuming: {before - len(lines)} already tested, {len(restored)} live restored"
            )
        journal.open(append=args.resume)
    logging.info(f"We have {len(lines)} proxy to check")

    if not lines and not restored:
        logging.error("No proxy to check")
        if journal:
            journal.close(remove=True)
        return None

    batch_size = 1 if args.no_batch else max(1, args.batch_size)
    threads = args.threads or (DEFAULT_THREADS_NO_BATCH if args.no_batch else DEFAULT_THREADS)

    cancel = threading.Event()
    previous = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGTERM, lambda *_: cancel.set())

    sink = ResultSink(
        args.output,
        live=args.live,
        fsync=args.fsync,
        limit=args.max_live,
        sort=args.sort,
        countries=args.country,
        rename=make_renamer(args.rename) if args.rename else None,
    )
    for result in restored:
        sink.add(result)
    show_bar = sys.stderr.isatty() and not (args.verbose or args.debug)
    stopped = "done"
    reporter = _Reporter(len(lines), show_bar)
    quiet = not (args.verbose or args.debug)
    try:
        with tempfile.TemporaryDirectory() as tempdir, reporter, _quiet_logging(quiet):
            cfg = CheckerCfg(
                core=spec,
                binary=binary,
                tempdir=tempdir,
                ready_timeout=args.t2exec,
                test_url=args.domain,
                timeout=args.timeout,
                geo=bool(args.geo or args.rename or args.country or args.sort == "country"),
                cancel=cancel,
                retries=max(0, args.retries),
                stable=max(1, args.stable),
                verify_url=args.verify,
            )
            try:
                if lines:
                    lines = _screen(lines, cfg, args, reporter, journal)
                if lines:
                    stopped = run_check(
                        lines,
                        cfg,
                        threads,
                        args.lport,
                        sink,
                        reporter,
                        batch_size=batch_size,
                        max_live=args.max_live,
                        journal=journal,
                    )
                if stopped == "max_live":
                    cancel.clear()  # that event only stopped the workers, which are gone
                if args.speedtest and stopped in ("done", "max_live") and sink.count:
                    reporter.stop_bar()  # the table must not be printed over a live bar
                    with (
                        Console(stderr=True).status(
                            f"measuring speed of the top {args.speedtest}...", spinner="dots"
                        )
                        if show_bar
                        else contextlib.nullcontext()
                    ):
                        table = _speedtest(sink, cfg, args)
                    if table is not None:
                        Console(stderr=args.output == "-").print(table)
            except KeyboardInterrupt:
                stopped = "interrupted"
    finally:
        sink.finalize()  # also on Ctrl+C / SIGTERM: partial results are kept
        if extra_formats:
            for path in write_formats(sink.ranked(), args.output, extra_formats, sink.line):
                logging.info(f"wrote {path}")
        if journal:
            journal.close(remove=stopped == "done")
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)

    summary = reporter.summary(stopped)
    if quiet and (reporter.counts["config_error"] or reporter.counts["error"]):
        summary += "\nrun with -v to see why configs failed"
    Console(stderr=True).print(summary, markup=False, highlight=False)
    return 130 if stopped == "interrupted" else None


def _order(lines: list[str], args) -> list[str]:
    """Shuffle if asked, but with --reuse keep last run's healthy proxies first so
    `-n` / `--max-live` try them before anything else."""
    prior: list[str] = []
    if args.reuse and args.output != "-" and (op := Path(args.output)).is_file():
        known = {proxy_identity(u) for u in parseContent(op.read_text(encoding="UTF-8").strip())}
        prior = [u for u in lines if proxy_identity(u) in known]
        lines = [u for u in lines if proxy_identity(u) not in known]
    if args.shuffle:
        random.shuffle(lines)
    return prior + lines


def _screen(
    lines: list[str], cfg: CheckerCfg, args, reporter: _Reporter, journal: Journal | None
) -> list[str]:
    """Settle everything that needs no core: unsupported configs, then servers that never
    answer a TCP connect. Returns the proxies that still need a real probe."""

    def settle(result: Result) -> None:
        reporter.update(result)
        if journal is not None:
            journal.record(result)

    candidates = []
    for url in lines:
        if (skipped := _precheck(url, cfg)) is not None:
            settle(skipped)
        else:
            candidates.append(url)
    if args.no_prefilter or not candidates:
        return candidates

    started = time.monotonic()
    kept, dropped = prefilter(
        candidates,
        timeout=args.prefilter_timeout,
        attempts=args.prefilter_attempts,
        cancel=cfg.cancel,
    )
    if cfg.cancel.is_set():
        return kept  # interrupted: don't record verdicts for a pass that was cut short
    for url in dropped:
        settle(Result(url, "unreachable", error="TCP connect failed"))
    logging.info(
        f"prefilter: {len(dropped)} of {len(candidates)} unreachable "
        f"({time.monotonic() - started:.1f}s)"
    )
    return kept


def _with_core(url: str, cfg: CheckerCfg, port: int, fn):
    """Run `fn(proxies)` against a fresh single-config core for *url*; None if it won't start."""
    config = cfg.core.write_config(url, port, cfg.tempdir, listen=CHECK_LISTEN)
    if config is None:
        return None
    try:
        with CoreProcess(cfg.core.run_argv(cfg.binary, config), port) as core:
            core.wait_ready(cfg.ready_timeout)
            return fn(socks_proxies(port))
    except (CoreExited, CoreNotReady) as err:
        logging.debug(f"speedtest: core for {url[:40]} failed: {err}")
        return None


def _failure_caption(errors: list[str], total: int, what: str = "download") -> str:
    """One line explaining why transfers failed, e.g. `download failed for 3/5: HTTP 429
    (rate limited) x2, timeout x1`. Full per-source reasons are in --format json."""
    kinds = Counter(
        "HTTP 429 (rate limited)"
        if "429" in e
        else "timeout"
        if "timeout" in e
        else "core did not start"
        if "core did not" in e
        else "failed"
        for e in errors
    )
    detail = ", ".join(f"{kind} x{n}" for kind, n in kinds.most_common())
    return f"{what} failed for {len(errors)}/{total}: {detail}"


def _speedtest(sink: ResultSink, cfg: CheckerCfg, args) -> Table | None:
    """Re-rank the best proxies by a steadier latency, then time real downloads on the
    top N one at a time (parallel tests would share, and so skew, your uplink). Returns the
    results table for the caller to print, or None if cancelled."""
    n = max(1, args.speedtest)
    (port,) = find_free_ports(args.lport, 1)
    pool = sorted(sink.all(), key=lambda r: r.latency_ms)[: n * 2]
    logging.info(f"speedtest: measuring latency of {len(pool)} candidates")

    measured = []
    for result in pool:
        if cfg.cancel.is_set():
            return None
        stats = _with_core(
            result.url,
            cfg,
            port,
            lambda px: measure_latency(args.domain, px, samples=5, timeout=args.timeout),
        )
        if stats is not None:
            measured.append(
                replace(result, latency_ms=round(stats.median_ms), jitter_ms=stats.jitter_ms)
            )
    measured.sort(key=lambda r: r.latency_ms)

    table = Table(title=f"speed test: top {min(n, len(measured))} by latency (speeds in Mbps)")
    # only the name column may shrink on a narrow terminal; numbers must stay readable
    table.add_column("#", justify="right", no_wrap=True, min_width=2)
    table.add_column("name", no_wrap=True, overflow="ellipsis")
    table.add_column("scheme", no_wrap=True)
    table.add_column("ms", justify="right", no_wrap=True, min_width=4)
    table.add_column("jitter", justify="right", no_wrap=True, min_width=6)
    table.add_column("down", justify="right", no_wrap=True, min_width=4)
    if args.speedtest_upload:
        table.add_column("up", justify="right", no_wrap=True, min_width=4)

    failures: list[str] = []
    up_failures: list[str] = []
    for rank, result in enumerate(measured[:n], 1):
        if cfg.cancel.is_set():
            return None
        mb = args.speedtest_mb

        def run(px, mb=mb):
            down = measure_download_any(
                px,
                download_urls(args.speedtest_url, int(mb * 1024 * 1024)),
                max_seconds=args.speedtest_time,
                max_bytes=int(mb * 1024 * 1024),
            )
            up = (
                measure_upload(px, base=args.speedtest_url, max_seconds=args.speedtest_time)
                if args.speedtest_upload
                else None
            )
            return down, up

        no_core = Transfer(None, error="core did not start")
        down, up = _with_core(result.url, cfg, port, run) or (no_core, no_core)
        result = replace(
            result,
            down_mbps=down.mbps,
            up_mbps=up.mbps if up else None,
            down_error=down.error,
            up_error=up.error if up else None,
            down_source=down.source,
        )
        sink.update(result)
        if args.speedtest_upload and (up is None or up.mbps is None):
            up_failures.append((up.error if up else "") or "")
        if down.mbps is None:
            failures.append(down.error or "")
        elif down.source and down.source != urlsplit(args.speedtest_url).hostname:
            logging.info(f"speedtest: {down.source} used for download (primary failed)")
        name = (proxy_name(result.url) or result.url)[:24]
        cells = [
            str(rank),
            f"{flag(result.country_code)} {name}" if result.country_code else name,
            result.url.split(":", 1)[0],
            str(result.latency_ms),
            f"{result.jitter_ms or 0:.1f}",
            f"{down.mbps:.1f}" if down.mbps is not None else "fail",
        ]
        if args.speedtest_upload:
            cells.append(f"{up.mbps:.1f}" if up and up.mbps is not None else "fail")
        table.add_row(*cells)
    for result in measured[n:]:  # keep the refined latency of the rest too
        sink.update(result)
    captions = []
    if failures:
        captions.append(_failure_caption(failures, len(measured[:n])))
    if up_failures:
        captions.append(_failure_caption(up_failures, len(measured[:n]), "upload"))
    if captions:
        table.caption = "; ".join(captions)
    return table


if __name__ == "__main__":
    sys.exit(main())
