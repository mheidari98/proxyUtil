"""0.6 features: sort/country/rename/formats, stable/verify/retries, speedtest, resume."""

import base64
import json
import threading
from pathlib import Path

import pytest

from proxyUtil import probe
from proxyUtil.cli import v2rayChecker as vc
from proxyUtil.geo import ExitInfo
from proxyUtil.probe import ProbeResult
from proxyUtil.results import (
    Journal,
    Result,
    ResultSink,
    format_paths,
    make_renamer,
    write_formats,
)
from tests.helpers import fake_spec, start_http

SS = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=") + "@1.2.3.4:8388"


def live(url, ms, cc=None, **kw):
    return Result(url, "live", ms, country_code=cc, **kw)


# ---------------------------------------------------------------- sink: sort / filter / rename
def test_sort_orders(tmp_path):
    rows = [
        live("vless://a@h:1", 30, "NL"),
        live("ss://b@h:1", 10, "DE"),
        live("trojan://c@h:1", 20),
    ]

    def order(sort):
        sink = ResultSink(str(tmp_path / "o"), sort=sort)
        for r in rows:
            sink.add(r)
        return [u.split(":")[0] for u in sink.sorted_urls()]

    assert order("latency") == ["ss", "trojan", "vless"]
    assert order("country") == ["ss", "vless", "trojan"]  # DE, NL, unknown last
    assert order("scheme") == ["ss", "trojan", "vless"]


def test_country_filter_keeps_only_matching_exits(tmp_path):
    sink = ResultSink(str(tmp_path / "o"), countries=frozenset({"DE", "NL"}))
    assert sink.add(live("ss://a@h:1", 1, "de"))
    assert sink.add(live("ss://b@h:1", 2, "NL"))
    assert not sink.add(live("ss://c@h:1", 3, "US"))
    assert not sink.add(live("ss://d@h:1", 4, None))  # unknown exit never matches a filter
    assert sink.count == 2


def test_rename_each_scheme_and_stream_writes_renamed_line(tmp_path):
    rename = make_renamer("{flag} {cc} {ms}ms | {name}")
    vless = rename(live("vless://a@h:1#orig", 120, "DE"))
    assert vless.endswith("#%F0%9F%87%A9%F0%9F%87%AA%20DE%20120ms%20%7C%20orig") or "DE" in vless
    out = tmp_path / "o.txt"
    sink = ResultSink(str(out), live=True, rename=rename)
    sink.add(live("vless://a@h:1#orig", 120, "DE"))
    assert "120ms" in __import__("urllib.parse").parse.unquote(out.read_text())
    # ss + vmess carry the name in different places; both must round-trip through parsers
    from proxyUtil.parsers import proxy_name

    assert proxy_name(rename(live(SS + "#n1", 5, "FR"))) == "🇫🇷 FR 5ms | n1"
    vm = (
        "vmess://"
        + base64.b64encode(
            json.dumps({"v": "2", "ps": "vmname", "add": "h", "port": "1", "id": "x"}).encode()
        ).decode()
    )
    assert proxy_name(rename(live(vm, 7, None))) == "🏳 ?? 7ms | vmname"


def test_rename_unknown_placeholder_is_blank_not_a_crash():
    assert "x" in make_renamer("{nonsense}x{name}")(live("vless://a@h:1#n", 1))


# ---------------------------------------------------------------- formats
def test_format_paths_and_collision():
    paths = format_paths("out/sorted.txt", ["json", "b64", "singbox"])
    assert paths["json"] == Path("out/sorted.json")
    assert paths["b64"] == Path("out/sorted.b64")
    assert paths["singbox"] == Path("out/sorted.singbox.json")
    assert format_paths("x.json", ["json"])["json"] == Path(
        "x.json"
    )  # collision detected by caller


def test_write_formats_json_b64_singbox(tmp_path):
    rows = [
        live(SS + "#a", 10, "DE", exit_ip="9.9.9.9", jitter_ms=1.5, down_mbps=42.0),
        live("trojan://pw@203.0.113.2:443?security=tls&sni=a.example#t", 20, "NL"),
    ]
    out = str(tmp_path / "o.txt")
    written = write_formats(rows, out, ["json", "b64", "singbox"])
    assert len(written) == 3

    data = json.loads((tmp_path / "o.json").read_text())
    assert (
        data[0]["country_code"] == "DE" and data[0]["down_mbps"] == 42.0 and data[0]["name"] == "a"
    )

    blob = base64.b64decode((tmp_path / "o.b64").read_text()).decode().split()
    assert blob == [r.url for r in rows]

    sb = json.loads((tmp_path / "o.singbox.json").read_text())
    tags = [o["tag"] for o in sb["outbounds"] if o["type"] not in ("urltest", "selector", "direct")]
    assert len(tags) == 2 and len(set(tags)) == 2
    groups = {o["tag"]: o for o in sb["outbounds"] if o["type"] in ("urltest", "selector")}
    assert groups["auto"]["outbounds"] == tags and groups["proxy"]["outbounds"] == ["auto", *tags]
    assert sb["route"]["final"] == "proxy"


def test_singbox_format_with_no_results_is_still_valid(tmp_path):
    write_formats([], str(tmp_path / "o.txt"), ["singbox"])
    sb = json.loads((tmp_path / "o.singbox.json").read_text())
    assert sb["route"]["final"] == "direct"


def test_singbox_format_validates_with_real_sing_box(tmp_path):
    import shutil
    import subprocess

    from proxyUtil.os_glue import augment_local_path

    augment_local_path()
    binary = shutil.which("sing-box")
    if not binary:
        pytest.skip("sing-box not installed")
    rows = [live(SS + "#a", 10), live("trojan://pw@203.0.113.2:443?security=tls#t", 20)]
    write_formats(rows, str(tmp_path / "o.txt"), ["singbox"])
    res = subprocess.run(
        [binary, "check", "-c", str(tmp_path / "o.singbox.json")], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stdout + res.stderr


# ---------------------------------------------------------------- probe options
def _seq(monkeypatch, outcomes):
    it = iter(outcomes)
    monkeypatch.setattr(probe, "probe_liveness", lambda *a, **k: next(it))


OK = lambda ms: ProbeResult(True, ms, 204)  # noqa: E731
BAD = ProbeResult(False, error="Timeout")


def test_stable_tolerates_one_miss_from_three_samples(monkeypatch):
    _seq(monkeypatch, [OK(30), BAD])
    res = probe.probe_stable(OK(10), "u", {}, 1, 3)
    assert res.ok and res.latency_ms == 20 and res.jitter_ms == 20.0


def test_stable_rejects_two_misses_and_any_miss_below_three(monkeypatch):
    _seq(monkeypatch, [BAD, BAD])
    assert "unstable: 2/3" in probe.probe_stable(OK(10), "u", {}, 1, 3).error
    _seq(monkeypatch, [BAD])
    assert not probe.probe_stable(OK(10), "u", {}, 1, 2).ok


def test_stable_one_sample_or_dead_first_is_passthrough():
    first = OK(5)
    assert probe.probe_stable(first, "u", {}, 1, 1) is first
    assert probe.probe_stable(BAD, "u", {}, 1, 5) is BAD


def test_retry_only_on_timeouts(monkeypatch):
    import requests

    calls = []

    def head(*a, **k):
        calls.append(1)
        raise requests.ConnectTimeout("slow")

    monkeypatch.setattr(probe.requests, "head", head)
    assert not probe.probe_liveness("http://x/generate_204", {}, 1, retries=2).ok
    assert len(calls) == 3
    calls.clear()

    def refused(*a, **k):
        calls.append(1)
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(probe.requests, "head", refused)
    assert not probe.probe_liveness("http://x/generate_204", {}, 1, retries=2).ok
    assert len(calls) == 1  # a refusal is not retried


# ---------------------------------------------------------------- checker integration
@pytest.fixture
def http():
    server, port = start_http()
    yield port
    server.shutdown()


def _cfg(spec, tmp_path, **kw):
    return vc.CheckerCfg(
        core=spec,
        binary=spec.binary,
        tempdir=str(tmp_path),
        ready_timeout=5,
        test_url="http://www.gstatic.com/generate_204",
        timeout=3,
        geo=kw.pop("geo", False),
        cancel=threading.Event(),
        **kw,
    )


def test_verify_stage_must_pass_too(tmp_path, http):
    spec = fake_spec(http)
    ok = vc.check_one(
        "ss://a@h:1#serve", 26001, _cfg(spec, tmp_path, verify_url="http://t.test/ok")
    )
    assert ok.status == "live"
    bad = vc.check_one(
        "ss://a@h:1#serve", 26002, _cfg(spec, tmp_path, verify_url="http://t.test/forbidden")
    )
    assert bad.status == "dead" and "verify failed" in bad.error


def test_stable_populates_jitter(tmp_path, http):
    res = vc.check_one("ss://a@h:1#serve", 26003, _cfg(fake_spec(http), tmp_path, stable=4))
    assert res.status == "live" and res.jitter_ms is not None


def test_geo_fields_flow_into_result_when_enabled(tmp_path, http, monkeypatch):
    monkeypatch.setattr(vc, "lookup_exit", lambda *_: ExitInfo("1.1.1.1", "NL", "Netherlands"))
    res = vc.check_one("ss://a@h:1#serve", 26004, _cfg(fake_spec(http), tmp_path, geo=True))
    assert (res.exit_ip, res.country_code, res.country) == ("1.1.1.1", "NL", "Netherlands")


# ---------------------------------------------------------------- journal / resume
def test_journal_roundtrip_with_torn_last_line(tmp_path):
    path = tmp_path / "o.txt.state"
    j = Journal(str(path))
    j.open(append=False)
    j.record(live("ss://a@h:1#x", 11, "DE"))
    j.record(Result("ss://b@h:1", "dead"))
    j.close()
    path.write_text(path.read_text() + '{"id": "torn", "stat')  # crash mid-write

    tested, restored = Journal(str(path)).load()
    assert tested == {"ss://a@h:1", "ss://b@h:1"}
    assert [(r.url, r.latency_ms, r.country_code) for r in restored] == [("ss://a@h:1#x", 11, "DE")]


def test_journal_removed_on_clean_close(tmp_path):
    j = Journal(str(tmp_path / "s"))
    j.open(append=False)
    j.close(remove=True)
    assert not (tmp_path / "s").exists()


def test_resume_end_to_end_with_real_main(tmp_path, http, monkeypatch):
    spec = fake_spec(http)
    monkeypatch.setattr(vc.cores, "pick_auto", lambda: spec)
    monkeypatch.setattr(vc.cores, "resolve", lambda s: s.binary)
    urls = [f"ss://u{i}@h:1#{'serve' if i % 2 else 'exit'}" for i in range(10)]
    inp, out = tmp_path / "in.txt", tmp_path / "out.txt"
    inp.write_text("\n".join(urls) + "\n")
    args = [
        "-f",
        str(inp),
        "-o",
        str(out),
        "-T",
        "4",
        "--no-prefilter",
        "-d",
        "http://x.test/generate_204",
        "-l",
        "27000",
    ]

    # a previous run that tested the first 6 proxies and was interrupted
    journal = Journal(f"{out}.state")
    journal.open(append=False)
    for url in urls[:6]:
        journal.record(live(url, 5) if "serve" in url else Result(url, "config_error", error="x"))
    journal.close()

    assert vc.main([*args, "--resume"]) is None
    got = set(out.read_text().split())
    assert got == {u for u in urls if u.endswith("serve")}  # restored 3 + freshly checked 2
    assert not Path(f"{out}.state").exists()  # completed run cleans its journal


def test_resume_skips_already_tested_proxies(tmp_path, http, monkeypatch):
    spec = fake_spec(http)
    monkeypatch.setattr(vc.cores, "pick_auto", lambda: spec)
    monkeypatch.setattr(vc.cores, "resolve", lambda s: s.binary)
    seen = []
    real = vc.check_one
    monkeypatch.setattr(vc, "check_one", lambda url, *a: seen.append(url) or real(url, *a))
    urls = [f"ss://u{i}@h:1#serve" for i in range(6)]
    inp, out = tmp_path / "in.txt", tmp_path / "out.txt"
    inp.write_text("\n".join(urls) + "\n")
    journal = Journal(f"{out}.state")
    journal.open(append=False)
    for url in urls[:4]:
        journal.record(live(url, 5))
    journal.close()
    vc.main(
        [
            "-f",
            str(inp),
            "-o",
            str(out),
            "--no-batch",
            "--no-prefilter",
            "-d",
            "http://x.test/generate_204",
            "-l",
            "27100",
            "--resume",
        ]
    )
    assert sorted(seen) == sorted(urls[4:])


# ---------------------------------------------------------------- cli wiring
def test_cli_rejects_bad_combinations(capsys):
    with pytest.raises(SystemExit):
        vc.main(["--format", "json", "-o", "-"])
    with pytest.raises(SystemExit):
        vc.main(["--sort", "speed"])
    with pytest.raises(SystemExit):
        vc.main(["--country", "Germany"])
    with pytest.raises(SystemExit):
        vc.main(["--format", "txt", "--format", "json", "-o", "same.json"])
    err = capsys.readouterr().err
    assert "-o -" in err and "--speedtest" in err and "ISO country codes" in err
    assert "overwritten" in err


def test_countries_parser():
    assert vc._countries("de, nl") == frozenset({"DE", "NL"})


def test_rename_and_country_imply_geo(tmp_path, http, monkeypatch):
    spec = fake_spec(http)
    monkeypatch.setattr(vc.cores, "pick_auto", lambda: spec)
    monkeypatch.setattr(vc.cores, "resolve", lambda s: s.binary)
    monkeypatch.setattr(vc, "lookup_exit", lambda *_: ExitInfo("1.1.1.1", "DE", "Germany"))
    inp, out = tmp_path / "in.txt", tmp_path / "out.txt"
    inp.write_text("vless://11111111-1111-1111-1111-111111111111@h:1?type=ws#orig\n")
    base = [
        "-f",
        str(inp),
        "-o",
        str(out),
        "--no-prefilter",
        "-d",
        "http://x.test/generate_204",
        "-l",
        "27200",
    ]
    assert vc.main([*base, "--rename"]) is None
    from urllib.parse import unquote

    assert "🇩🇪 DE" in unquote(out.read_text()) and "| orig" in unquote(out.read_text())
    assert vc.main([*base, "--country", "NL"]) is None  # exit is DE: filtered out
    assert out.read_text() == ""


# ---------------------------------------------------------------- speedtest end to end
def test_speedtest_stage_ranks_top_n_and_records_speeds(tmp_path, monkeypatch, capsys):
    from http.server import ThreadingHTTPServer

    from tests.test_geo_speed import Handler

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    spec = fake_spec(server.server_address[1])
    monkeypatch.setattr(vc.cores, "pick_auto", lambda: spec)
    monkeypatch.setattr(vc.cores, "resolve", lambda s: s.binary)
    urls = [f"ss://u{i}@h:1#serve" for i in range(5)]
    inp, out = tmp_path / "in.txt", tmp_path / "out.txt"
    inp.write_text("\n".join(urls) + "\n")
    try:
        code = vc.main(
            [
                "-f",
                str(inp),
                "-o",
                str(out),
                "--no-prefilter",
                "-l",
                "27300",
                "-T",
                "5",
                "--speedtest",
                "2",
                "--speedtest-url",
                "http://speed.test",
                "--speedtest-mb",
                "1",
                "--speedtest-time",
                "3",
                "--speedtest-upload",
                "--format",
                "json",
                "--sort",
                "speed",
                "-d",
                "http://x.test/generate_204",
            ]
        )
    finally:
        server.shutdown()
    assert code is None
    captured = capsys.readouterr()
    shown = captured.out
    assert "speed test: top 2" in shown and "Mbps" in shown, captured.err
    rows = json.loads((tmp_path / "out.json").read_text())
    assert len(rows) == 5
    tested = [r for r in rows if r["down_mbps"]]
    assert len(tested) == 2 and all(r["up_mbps"] for r in tested)
    assert [r["down_mbps"] for r in rows[:2]] == sorted(
        (r["down_mbps"] for r in tested), reverse=True
    )
    assert all(r["jitter_ms"] is not None for r in rows[:2])  # refined latency recorded


def test_speedtest_default_count_is_ten():
    assert vc.build_parser().parse_args(["--speedtest"]).speedtest == 10
    assert vc.build_parser().parse_args(["--speedtest", "3"]).speedtest == 3
    assert vc.build_parser().parse_args([]).speedtest is None


def test_renamed_lines_are_single_tokens_and_reparse_for_every_scheme():
    # Regression: names with spaces / '|' were written raw into the fragment, so the line
    # split on whitespace when re-read (this tool, or any client) and lost the name.
    from proxyUtil.parsers import parseContent, proxy_name
    from proxyUtil.uri import quote_fragment

    vm = (
        "vmess://"
        + base64.b64encode(
            json.dumps({"v": "2", "ps": "o", "add": "h", "port": "1", "id": "x"}).encode()
        ).decode()
    )
    urls = [
        "vless://11111111-1111-1111-1111-111111111111@h:1?type=ws#o",
        "trojan://pw@h:1?security=tls#o",
        "hysteria2://pw@h:1#o",
        "anytls://pw@h:1#o",
        SS + "#o",
        vm,
    ]
    rename = make_renamer("{flag} {cc} {ms}ms | {name}")
    for url in urls:
        line = rename(live(url, 120, "DE"))
        assert len(line.split()) == 1, line  # no raw whitespace
        assert parseContent(line) == [line]  # survives re-reading
        if not url.startswith("vmess"):
            assert "|" not in line.split("#", 1)[1]
        assert proxy_name(line) == "🇩🇪 DE 120ms | o"
        # renaming twice must not stack or truncate names
        assert proxy_name(rename(live(line, 50, "DE"))) == "🇩🇪 DE 50ms | 🇩🇪 DE 120ms | o"
    assert quote_fragment("Woman,Life,Freedom") == "Woman,Life,Freedom"  # readable ASCII untouched
    assert quote_fragment("a b|c#d%") == "a%20b%7Cc%23d%25"
