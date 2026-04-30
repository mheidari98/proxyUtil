"""Unit tests for misc pure helpers in proxyUtil.myUtil."""

import functools
import operator

from proxyUtil.myUtil import (
    checkPatternsInList,
    is_json,
    mergeMultiDicts,
    parseContent,
    split2Npart,
    tagChanger,
)


def test_split2Npart_distributes_items():
    parts = list(split2Npart(list(range(10)), 3))
    assert len(parts) == 3
    assert sum(len(p) for p in parts) == 10
    # round-robin reassembled stays sorted (not guaranteed, but slicing preserves order)
    assert functools.reduce(operator.iadd, parts, []) == list(range(10))


def test_split2Npart_more_buckets_than_items():
    parts = list(split2Npart([1, 2], 4))
    assert len(parts) == 4
    assert functools.reduce(operator.iadd, parts, []) == [1, 2]


def test_mergeMultiDicts():
    out = mergeMultiDicts({"a": 1}, {"b": 2}, {"a": 99})
    # later dicts override earlier
    assert out == {"a": 99, "b": 2}


def test_is_json_true_false():
    assert is_json('{"a": 1}') is True
    assert is_json("not json") is False


def test_checkPatternsInList_finds_vmess():
    lines = [
        "junk vmess://abcd1234 trailing",
        "no proxy here",
        "ss://userpw@host:8388  comment",
    ]
    out = checkPatternsInList(lines)
    assert "vmess://abcd1234" in out
    assert any(s.startswith("ss://") for s in out)


def test_parseContent_picks_up_proxy_lines(sample_ss_url):
    blob = f"line1\n{sample_ss_url}\nline2\n"
    out = parseContent(blob)
    assert sample_ss_url in out


def test_tagChanger_replaces_tag(sample_ss_url):
    new = tagChanger(sample_ss_url, "newtag")
    # tag is the part after '#' — body is allowed to be re-normalized
    assert new.endswith("#newtag")
    assert new.startswith("ss://")
