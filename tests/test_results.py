import os

from proxyUtil.results import Result, ResultSink


def live(url, ms):
    return Result(url, "live", ms)


def test_default_writes_nothing_until_finalize_then_sorted(tmp_path):
    out = tmp_path / "o.txt"
    sink = ResultSink(str(out))
    sink.add(live("ss://slow", 300))
    sink.add(live("ss://fast", 20))
    assert not out.exists()
    sink.finalize()
    assert out.read_text() == "ss://fast\nss://slow\n"


def test_non_live_and_duplicates_are_ignored(tmp_path):
    sink = ResultSink(str(tmp_path / "o.txt"))
    assert not sink.add(Result("ss://a", "dead"))
    assert sink.add(live("ss://a", 5))
    assert not sink.add(live("ss://a", 1))
    assert sink.count == 1


def test_live_mode_is_on_disk_immediately(tmp_path):
    out = tmp_path / "o.txt"
    sink = ResultSink(str(out), live=True)
    sink.add(live("ss://one", 50))
    assert out.read_text() == "ss://one\n"  # visible before finalize
    sink.add(live("ss://two", 10))
    sink.finalize()
    assert out.read_text() == "ss://two\nss://one\n"


def test_empty_result_writes_empty_file(tmp_path):
    out = tmp_path / "o.txt"
    ResultSink(str(out)).finalize()
    assert out.read_text() == ""


def test_finalize_is_atomic_and_leaves_no_tmp(tmp_path, monkeypatch):
    out = tmp_path / "o.txt"
    out.write_text("previous\n")
    sink = ResultSink(str(out))
    sink.add(live("ss://x", 1))

    def boom(*_):
        raise OSError("crash between write and replace")

    monkeypatch.setattr(os, "replace", boom)
    try:
        sink.finalize()
    except OSError:
        pass
    assert out.read_text() == "previous\n"
    assert not (tmp_path / "o.txt.tmp").exists()


def test_stdout_streams_with_live_and_prints_once_without(capsys):
    sink = ResultSink("-", live=True)
    sink.add(live("ss://a", 2))
    assert capsys.readouterr().out == "ss://a\n"
    sink.finalize()
    assert capsys.readouterr().out == ""

    sink = ResultSink("-")
    sink.add(live("ss://b", 9))
    sink.add(live("ss://a", 2))
    assert capsys.readouterr().out == ""
    sink.finalize()
    assert capsys.readouterr().out == "ss://a\nss://b\n"
