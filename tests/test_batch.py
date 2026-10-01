"""Batch mode: one core process serving many proxies, with validation + fallback."""

import queue
import threading

import pytest

from proxyUtil import batch, cores, runner
from proxyUtil.cli import v2rayChecker as vc
from proxyUtil.results import ResultSink
from tests.helpers import fake_spec, start_http


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
        geo=False,
        cancel=threading.Event(),
        **kw,
    )


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def test_validate_isolates_bad_configs_by_bisection(tmp_path, http):
    spec = fake_spec(http)
    items = [(f"ss://u{i}@h:1#{'exit' if i in (3, 11) else 'serve'}", 25000 + i) for i in range(16)]
    good, bad = batch.validate_items(spec, spec.binary, items, str(tmp_path))
    assert {u for u, _ in bad} == {items[3][0], items[11][0]}
    assert len(good) == 14
    assert all("unknown cipher" in reason for _, reason in bad)


def test_validate_all_good_costs_one_check(tmp_path, http, monkeypatch):
    spec = fake_spec(http)
    calls = []
    real = batch.check_config
    monkeypatch.setattr(batch, "check_config", lambda *a: calls.append(1) or real(*a))
    items = [(f"ss://u{i}@h:1#serve", 25100 + i) for i in range(10)]
    good, bad = batch.validate_items(spec, spec.binary, items, str(tmp_path))
    assert len(good) == 10 and not bad and len(calls) == 1


def test_check_batch_one_result_per_url_one_process(tmp_path, http):
    spec = fake_spec(http)
    urls = [f"ss://u{i}@h:1#{'exit' if i % 5 == 0 else 'serve'}" for i in range(10)]
    urls.append("hysteria2://pw@h:1")  # fake core doesn't speak it
    results = queue.Queue()
    vc.check_batch(urls, list(range(25200, 25211)), results, _cfg(spec, tmp_path))
    got = {r.url: r for r in _drain(results)}
    assert set(got) == set(urls)
    assert sum(r.status == "live" for r in got.values()) == 8
    assert sum(r.status == "config_error" for r in got.values()) == 2
    assert got["hysteria2://pw@h:1"].status == "unsupported"
    assert runner.live_count() == 0


def test_check_batch_falls_back_to_per_process_when_batch_cannot_start(tmp_path, http):
    base = fake_spec(http)
    # validation lies (always passes) but the batch process itself crashes on a bad entry
    lying = cores.CoreSpec(
        name="fake",
        binary=base.binary,
        schemes=base.schemes,
        write_config=base.write_config,
        run_argv=base.run_argv,
        build_batch=base.build_batch,
        check_argv=lambda binary, config: [binary, "-c", "pass"],
    )
    urls = [f"ss://u{i}@h:1#{'exit' if i == 2 else 'serve'}" for i in range(6)]
    results = queue.Queue()
    vc.check_batch(urls, list(range(25300, 25306)), results, _cfg(lying, tmp_path))
    got = {r.url: r.status for r in _drain(results)}
    assert len(got) == 6
    assert got[urls[2]] == "config_error"
    assert [s for u, s in got.items() if u != urls[2]] == ["live"] * 5
    assert runner.live_count() == 0


def test_run_check_batch_mode_matches_per_process_mode(tmp_path, http):
    spec = fake_spec(http)
    urls = [f"ss://u{i}@h:1#{'exit' if i % 4 == 0 else 'serve'}" for i in range(24)]

    def run(batch_size):
        sink = ResultSink(str(tmp_path / f"o{batch_size}.txt"))
        rep = vc._Reporter(len(urls), show_bar=False)
        stopped = vc.run_check(
            urls, _cfg(spec, tmp_path), 8, 25400, sink, rep, batch_size=batch_size
        )
        assert stopped == "done"
        return set(sink.sorted_urls()), dict(rep.counts)

    assert run(1) == run(8)
    assert runner.live_count() == 0


def test_max_live_stops_early_and_limits_output(tmp_path, http):
    spec = fake_spec(http)
    urls = [f"ss://u{i}@h:1#serve" for i in range(60)]
    out = tmp_path / "o.txt"
    sink = ResultSink(str(out), limit=3)
    rep = vc._Reporter(len(urls), show_bar=False)
    stopped = vc.run_check(
        urls, _cfg(spec, tmp_path), 6, 25500, sink, rep, batch_size=6, max_live=3
    )
    sink.finalize()
    assert stopped == "max_live"
    assert len(out.read_text().split()) == 3
    assert sum(rep.counts.values()) < 60
    assert runner.live_count() == 0
