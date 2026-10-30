from proxyUtil import health

A = "vless://a@a.example.net:443"
B = "vless://b@b.example.net:443"
C = "vless://c@c.example.net:80"
URLS = [A, B, C]
B_KEY = "b.example.net:443"


def test_new_endpoint_that_fails_is_dropped_at_once():
    kept, strikes = health.apply_strikes(URLS, {B_KEY}, published=set(), strikes={})
    assert kept == [A, C]
    assert strikes == {}


def test_published_endpoint_gets_strikes_before_it_is_dropped():
    strikes: dict[str, int] = {}
    for expected in (1, 2):
        kept, strikes = health.apply_strikes(URLS, {B_KEY}, {B_KEY}, strikes)
        assert kept == URLS
        assert strikes == {B_KEY: expected}
    kept, strikes = health.apply_strikes(URLS, {B_KEY}, {B_KEY}, strikes)
    assert kept == [A, C]
    assert strikes == {}


def test_recovery_clears_the_strikes():
    _, strikes = health.apply_strikes(URLS, set(), {B_KEY}, {B_KEY: 2})
    assert strikes == {}


def test_configs_a_connect_cannot_judge_are_kept():
    udp = "hy2://pw@u.example.net:443?sni=x"
    kept, _ = health.apply_strikes([udp], {"u.example.net:443"}, set(), {})
    assert kept == [udp]


def test_offline_runner_keeps_everything_and_blames_nobody(monkeypatch):
    monkeypatch.setattr(health, "runner_is_online", lambda: False)
    kept, strikes, note = health.filter_configs(URLS, {"a.example.net:443"}, {"x:1": 1})
    assert (kept, strikes) == (URLS, {"x:1": 1})
    assert "offline" in note


def test_everything_failing_means_the_check_is_broken(monkeypatch):
    monkeypatch.setattr(health, "runner_is_online", lambda: True)
    monkeypatch.setattr(
        health, "probe", lambda urls: {"a.example.net:443", B_KEY, "c.example.net:80"}
    )
    kept, _, note = health.filter_configs(URLS, set(), {})
    assert kept == URLS
    assert "skipped" in note


def test_filters_failed_endpoints(monkeypatch):
    monkeypatch.setattr(health, "runner_is_online", lambda: True)
    monkeypatch.setattr(health, "probe", lambda urls: {"c.example.net:80"})
    kept, _, note = health.filter_configs(URLS, set(), {})
    assert kept == [A, B]
    assert note == ""
