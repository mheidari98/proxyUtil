# Changes

## 0.5.0 — v2rayChecker overhaul

Measured on the 13,813-proxy bench dump (live counts there are stale; timings are real):

| core     | before (May bench) | now     |
|----------|-------------------:|--------:|
| sing-box |             264 s  | 134 s   |
| xray     |             450 s  | 140 s   |
| v2ray    |             483 s  | 199 s   |

62% of servers are rejected by a TCP connect before any core starts, and memory no longer
scales with concurrency (one core process serves a whole batch of proxies).

### Breaking (v2rayChecker)
- **Default core is `auto`** (sing-box if installed, else xray, else v2ray). sing-box speaks
  every scheme and legacy ss ciphers; use `-c xray|v2ray|sing-box` to force one.
- **Default concurrency is `-T 300`** (was 10) because batch mode makes it cheap;
  `--no-batch` restores one-process-per-proxy and the old default of 10.
- **Geo lookup no longer decides liveness.** It used to run for every live proxy and drop the
  proxy if ip-api failed (20% of live xray configs in the May bench). Geo is now opt-in via
  `--geo` (implied by `--rename`, `--country`, `--sort country`), and a failed lookup only
  means "no country". `-i/--ignore` (which worked backwards) is a deprecated no-op that warns.
- **Default probe target is HTTPS** (`https://www.gstatic.com/generate_204`, was plain HTTP).
  On the free list 35 of 60 "live" proxies answered plain HTTP but black-holed TLS, so they
  were useless for real traffic. Latency now includes the TLS handshake. Use
  `-d http://www.gstatic.com/generate_204` for the old behaviour.
- **Stricter probe.** `generate_204` endpoints must answer exactly 204; any other `-d` target
  must answer 2xx/3xx. Block pages and captive portals no longer count as live; expect lower
  (more honest) counts. Latency is real milliseconds (was 10 ms units).
- `--t2exec` is now the *maximum* wait for a core to open its ports (default 5 s) instead of a
  fixed sleep; the checker proceeds as soon as they are up (~25 ms). `--t2kill` is a
  deprecated no-op. `-t/--timeout` accepts floats.
- Exit code is 130 when interrupted. `--url` is repeatable on `v2rayChecker`, `shadowChecker`
  and `clashGen`; collected proxies keep first-seen order.

### Fixes
- **xray 26 rejected every TLS config.** The xray templates hardcoded `allowInsecure: true`,
  and xray-core removed it on 2026-06-01 (`"allowInsecure" will be removed automatically after
  2026-06-01`). Every TLS vmess/vless/trojan failed, silently counted as "dead". Templates no
  longer force it. Configs that explicitly ask to skip certificate verification are reported
  as unsupported by xray with a pointer to `-c sing-box`.
- A core that exits before opening its port (e.g. `unknown cipher method: aes-256-cfb`, which
  explained xray finding 26 live ss configs vs sing-box's 397) is `config_error` with the
  core's own message, not a dead proxy. xray/v2ray cipher support was verified against the real
  binaries (v2ray lacks xchacha20 and ss-2022) and unsupported configs are skipped up front.
- **Security:** the checker's xray inbound bound `0.0.0.0` with no auth, turning every config
  under test into an open proxy. It now binds `127.0.0.1` (`createConfig(listen=...)`;
  `connectMe` keeps its previous default).
- Ctrl+C / SIGTERM: partial results are written (atomically) and every spawned core is killed
  and reaped. No orphaned processes or zombies; core stdout is no longer an unread pipe.
- A batch is only "ready" once *all* of its ports accept connections (cores don't open inbounds
  in config order; waiting for the last one caused intermittent connection-refused).
- vmess/vless configs with junk transport fields (`net=""`, `ws🌐`, `tcp@channel`, missing
  `net`/`tls`) are normalised instead of warning or crashing (`utils.normalize_network`).
- Free-port search binds instead of connecting, so bound-but-idle ports are skipped. Raises the
  open-file limit when it can (pre-filter uses up to 2000 sockets).
- Probe errors now name the root cause (`NewConnectionError: ... Connection refused`).

- **Renamed proxies were not valid URLs.** Names are now percent-encoded in the fragment
  (`uri.quote_fragment`, also used by `tagChanger` and the ss builder). Raw spaces and `|`
  split the line when re-read and broke client imports. Re-running `--rename` on an already
  renamed list nests the old name inside the new one.

### Features
- **TCP pre-filter** (`proxyUtil.prefilter`): servers that never answer a TCP connect are
  dropped without starting a core. UDP schemes (hy/hy2/tuic/juicity/wireguard) and kcp/quic
  transports are never judged by it. `--no-prefilter`, `--prefilter-timeout`,
  `--prefilter-attempts`.
- **Batch mode** (`proxyUtil.batch`, default): one core process serves up to `--batch-size`
  (100) proxies via an inbound+outbound pair each. The config is validated with the core's own
  checker (`xray run -test`, `v2ray test`, `sing-box check`) and bisected to isolate bad
  outbounds; if a batch still can't start it falls back to a process per proxy.
  `--no-batch` disables it.
- Duplicates that differ only by name (URL fragment / vmess `ps`) are tested once.
- Shared work queue instead of static partitioning (no straggler tail).
- `--max-live K` stops once K healthy proxies are found; with `--reuse`, last run's healthy
  proxies are tried first.
- `--live` appends each healthy proxy to the output as it is found (`--fsync` for durability,
  `-o -` for stdout); the file is rewritten sorted at the end. Use `tail -F`.
- `--resume` skips proxies an interrupted run already tested (journal `<output>.state`,
  removed after a completed run).
- **Country and naming:** exit country is resolved *through the proxy* (Cloudflare
  `cdn-cgi/trace`, ip-api fallback), so CDN-fronted configs get the real exit country.
  `--country DE,NL` filters, `--rename [TEMPLATE]` rewrites names (default `🇩🇪 DE | original`; add latency
  with a custom template such as `'{flag} {cc} {ms}ms | {name}'`), `--sort latency|country|scheme|speed`. Opt-in; default output is
  byte-identical to the input URLs.
- `--format txt|json|b64|singbox` (repeatable): full result data, a base64 subscription, or a
  ready-to-import sing-box client config with a `urltest` group.
- `--retries N` (timeouts only), `--stable K` (K probes, tolerate one miss, report median
  latency + jitter), `--verify URL` (second-stage target, e.g. `https://web.telegram.org`).
- `--speedtest [N]` (default 10): re-measures latency/jitter of the best candidates, then times
  real downloads of the top N one at a time and shows a table; `--speedtest-time`,
  `--speedtest-mb`, `--speedtest-upload`, `--speedtest-url`.
- Sources: `--sources FILE`, concurrent fetch, failed sources are logged with the reason.
- Progress bar (TTY) and an end-of-run summary by status and by scheme. Per-config build
  errors and transport warnings are hidden in a normal run (they scribble over the bar and
  the summary already counts them); `-v` shows them.
- New modules: `runner`, `probe`, `results`, `prefilter`, `batch`, `geo`, `speedtest`.
  `scripts/bench_checker.py` replaces the ad-hoc bench script.

### Not done
- Offline GeoIP database (`--geo server`): the through-the-proxy lookup is free and more
  accurate for CDN-fronted configs, so a mmdb dependency wasn't worth it yet.
- `--config` TOML file: `tomllib` needs Python 3.11 and the package floor is 3.10.

## Unreleased — modernize sweep across the package

Backwards-compatible code-quality pass; no scheme matrix or CLI surface change.

### Modernization
- `match`/`case` dispatch in `singbox.build_singbox_config`, `singbox._transport_block`,
  `xray.createConfig`, `xray.createTrojanConfig` transport, `os_glue.get_OS`/`get_arch`,
  `cores.resolve` install dispatch.
- Walrus `:=` in `parsers.tagsChanger`/`parseTrojan`/`checkPatternsInList`,
  `_common.collect_proxies`, `cfRecorder` IP filter, `clashGen._get_rule_set`,
  `singbox._transport_block`.
- Dispatch tables: `parsers._IP_EXTRACTORS`, `parsers._PATTERN_RES` (per-scheme regex,
  pre-compiled once — removes quadratic compile in batch hot path), `clashGen._BEHAVIOR_PREFIX`,
  `cores.REGISTRY` built via dict-comp.
- Pathlib at every IO call site (replaces `os.path.join`, `os.remove`, manual `open` for
  read/write of small files).
- Comprehensions over loops in `processShadowJson`, `parse_ssr` decoder, `dnsChecker`
  triple-loop, `clashGen` rule flatten, sort-output writers.
- `dnsUtil`: 3 resolver functions factored through one `_resolve(query_fn)` helper.
- `logFormatter.CustomFormatter`: pre-built one `Formatter` per level as ClassVar (was
  instantiating a fresh `Formatter` per log record).
- `utils.finder`: `lru_cache` over the compiled regex; `re.escape` on the flag.

### Bug fixes
- `ipExtractor --sort` no longer crashes on IPv6 (was using `IPv4Address` for the sort key).
- `parsers.parse_ss`/`parse_ss_withPlugin`/`parseVless`/`parseTrojan` raise `ValueError`
  with a useful message instead of `AttributeError` on `None.groups()` for malformed URLs.
- `net.getIP` returns `None` (not `False`) on resolve failure — truthiness contract intact.
- `dnsUtil.Do53_resolver` added as the spelled name; `Do53_reolver` kept as alias.
- `connectMe`: when the picked core fails to write a config, fall through to the
  system-proxy cleanup instead of returning early.
- `v2rayChecker` / `shadowChecker`: empty result no longer writes a stray `\n` to the
  output file.

## 0.4.0 — module split + unified `--core` + full scheme matrix

### Package layout (breaking)

`proxyUtil/myUtil.py` and `proxyUtil/network.py` deleted. The 1100-line god
file split into focused modules:

- `proxyUtil/utils.py` — `base64Decode`, `isBase64`, `is_json`, `is_valid_uuid`,
  `generate_uuid`, `getSHA256`, `mergeMultiDicts`, `split2Npart`, `finder`,
  `silentremove`.
- `proxyUtil/schemes.py` — scheme constants + `proxyScheme` list.
- `proxyUtil/uri.py` — `Create_ss_url`, `Create_ss_url_withPlugin`,
  `Create_vmess_url`, `processShadowJson`.
- `proxyUtil/parsers.py` — every `parse_*`, `parseContent`,
  `checkPatternsInList`, `extractIPs`, `tagChanger`, `tagsChanger`. Adds
  parsers for hysteria2/hy2, hysteria, tuic, anytls, shadowtls, naive, ssh,
  wireguard, juicity.
- `proxyUtil/shadowsocks.py` — `ssURI2sslocal`, `sslocal2ssURI`, `ssConfig2json`.
- `proxyUtil/net.py` — `ScrapURL`, `downloadZray`, `downloadSingBox`,
  `getIPnCountry`, `is_alive`, `getIP`, `_format_geo`, `IP_API_URL`, `PROXIES`.
- `proxyUtil/os_glue.py` — OS / process helpers (`get_OS`, `get_arch`,
  `is_tool`, `is_port_in_use`, `unixRunCore`/`winRunCore`/`unixKillCore`/
  `winKillCore`, `killProcess`, `installDocker`, `chmodX`, `set_proxychains`,
  `set_system_proxy`, `clearScreen`, `PROXYCHAINS`).
- `proxyUtil/xray.py` — xray/v2ray config templates + builders + transport
  dispatch table + `writeConfig(url, port, path) -> path`.
- `proxyUtil/singbox.py` — sing-box config builder for every supported scheme,
  including the schemes xray-core does not speak.
- `proxyUtil/cores.py` — `REGISTRY` mapping `name -> CoreSpec`; one source of
  truth for `--core`.

External callers MUST update `from proxyUtil.myUtil import X` to the new module
paths. There is no shim. Wildcard imports were never re-exported, so this
mostly affects tests / downstream library users; CLI entry-points are unchanged.

### Unified `--core` selector

`v2rayChecker -c {xray, v2ray, sing-box}` now picks ONE binary. The chosen
core's `schemes` attribute decides which URLs are validated; everything else
gets a one-line debug log and is skipped. No more `core_paths` dict, no more
hardcoded `_SINGBOX_SCHEMES`, no more silent xray→sing-box fallback. Pick
`sing-box` to validate hysteria2 / hy2 / tuic / hysteria / anytls in a mixed
dump.

### Full scheme matrix in sing-box backend

sing-box now emits outbounds for: vmess, vless, trojan, ss, hysteria,
hysteria2/hy2, tuic, anytls (≥ 1.11), shadowtls (v3), naive (`naive+https://`),
ssh, wireguard, juicity (lossy: emitted as tuic v5 + bbr+native).

Reality is enforced as a 3-flag invariant
(`tls.enabled` + `tls.reality.enabled` + `tls.utls.enabled`) — common bug source
the spec research surfaced. xray-only `xhttp` / `splithttp` transports are
auto-downgraded to sing-box `httpupgrade` with a one-line warning.

### Xray variant coverage expanded

- ws transport accepts `?ed=2048` and appends it to the path (xray's
  early-data convention).
- gRPC: `mode=multi → multiMode=true`, `mode=gun → multiMode=false`. `authority`
  preserved.
- xhttp `extra` is JSON-decoded into a sub-object.
- KCP `seed` + `headerType` propagated.
- QUIC `quicSecurity` + `key` + `headerType` propagated.
- Reality `alpn`, `pbk`, `sid`, `spx` mapped to JSON.

### CLI consolidation

`cdnGen`, `cfRecorder`, `dnsChecker`, `ipExtractor`, `v2rayChecker` moved into
`proxyUtil/cli/`; top-level shim files preserve `python -m
proxyUtil.v2rayChecker` etc. `pyproject.toml [project.scripts]` rewired to the
`proxyUtil.cli.<name>:main` form for all 10 entry-points.

### connectMe

Now uses the core registry: `-c xray|v2ray|sing-box|ss`. Auto-downloads
sing-box on first run when missing.

## 0.3.0 — sing-box backend + new schemes + cleanup

### New protocol coverage
- New `proxyUtil/singbox.py` module: emits sing-box outbound JSON for
  `hysteria2://`, `hy2://`, `hysteria://`, `tuic://`, `anytls://`, plus
  sing-box variants of `ss/vmess/vless/trojan`. Includes parsers
  `parseHysteria2`, `parseHysteria`, `parseTuic`, `parseAnytls`.
- `createConfig` now returns `(configName, core_name)` and dispatches
  hy2/tuic/hy/anytls to sing-box, keeping xray for the existing schemes.
- `v2rayChecker` resolves both xray and (optional) sing-box on PATH and selects
  the right binary per-URL; missing sing-box logs an actionable error and skips
  affected URLs without aborting the batch.
- Empirical scheme histogram across the 50+ subscription URLs in
  `mheidari98/.proxy/nodes.md` confirmed real-world hy2/tuic/hysteria samples
  (used to derive parser fixtures).

### xray transport + security widening
- Refactored `createVmessConfig` into a transport dispatch table covering
  `tcp/raw/ws/h2/http/grpc/kcp/quic/httpupgrade/splithttp/xhttp`. New TLS
  options: `fp`, `alpn`, `echSettings`, REALITY `alpn`, gRPC `multiMode`/`authority`,
  KCP `seed/headerType`, TCP `headerType=http`. Filter `flow` to only the
  current `xtls-rprx-vision[-udp443]`.
- `createTrojanConfig`: added explicit `h2/http` branch, default ws `path=/`,
  gRPC `serviceName` fallback to `path`, propagate `fp/alpn`, `tlsSettings.fingerprint`.
- `parseTrojan`: alias `peer→sni`, normalize `allowinsecure` casing/truthiness.
- `parse_ssr`: tolerate URLs without trailing `/?` query.
- `parse_ss_withPlugin`: stop double-base64-decoding plain SIP002 userinfo;
  detect SS-2022 ciphers and emit `uot:true, UoTVersion:2`.
- Plugin allow-list warning for unknown SIP003 plugins.

### v2rayChecker — perf, safety, cleanliness
- Replace module-level globals (`CORE`, `time2exec`, `time2kill`, `ignoreWarning`,
  `CTRL_C`, `tempdir`) with a `CheckerCfg` dataclass + `threading.Event` cancel.
- Wrap proc lifecycle in `try/finally` so `killer(proc)` always runs.
- `tempfile.TemporaryDirectory()` ensures cleanup on early exit.
- Drop the duplicate `as_completed` loop — collect results in one pass.

### Shared CLI plumbing
- New `_common.add_source_args` / `collect_proxies` / `find_free_ports`. Wired
  into `v2rayChecker`, `shadowChecker`, and `clashGen`.
- `shadowChecker`: replace `os.system` shell calls with `subprocess.run` +
  `os.kill`; reuse `getIPnCountry` instead of inlining the ip-api request.
- `getIPnCountry`: returns `(ip, country, country_code)`, narrows except
  list, hoists `IP_API_URL` to module-level constant.

### .gitignore
- Added `xray/`, `v2ray/`, `sing-box/`, `all`, `sortedProxy.txt`,
  `sortedShadow.txt`, `clashConfig.yaml`, `*.session`, `geoip*.mmdb`,
  `geosite*.dat`, `*.mmdb`, `*.dat`.

## 0.2.0 — modernize

### Follow-up cleanup (post-initial-modernize commit)
- New `proxyUtil/network.py` containing `ScrapURL` and `downloadZray` — the only
  network-side-effecting helpers in the package, now isolated.
- Drop `from proxyUtil import *` from the 4 legacy CLIs; every CLI uses explicit imports.
- `proxyUtil/__init__.py` no longer wildcard-re-exports; only `__version__` is public.
- Every submodule (`myUtil`, `dnsUtil`, `dnsUrl`, `network`, `logFormatter`, `_common`) now
  defines an explicit `__all__`.
- Drop all `F403`/`F405` ruff per-file ignores.
- Add `basedpyright` (standard mode) to dev deps and CI.
- Add `.pre-commit-config.yaml` (ruff + standard hygiene hooks).
- Gate publish workflow with `workflow_dispatch` (target = `test` or `prod`); tag-pushes
  still publish to both.
- README rewritten to point at the new uv/ruff/pytest/basedpyright workflow.

### Initial modernize commit

Breaking modernization. Drops Python <3.10. New tooling: `uv` + `pyproject.toml` (hatchling).

### Build / packaging
- Replace `setup.py` + `setup.cfg` + `MANIFEST.in` + `requirements.txt` with a single
  `pyproject.toml` (hatchling backend, dynamic version from `proxyUtil/__version__.py`).
- Add `uv.lock` for reproducible installs.
- New `Makefile` is a thin wrapper over `uv run`.
- `uv build` produces sdist + wheel; data file `Clash-Template.yaml` ships in the wheel
  via hatchling auto-include.

### Python + deps
- Floor: Python 3.10. CI matrix: 3.10, 3.11, 3.12.
- Drop dead deps: `numpy` (zero `np.` references), `cryptography`, `httpx`, `jsonlines`,
  `Pygments`, `PyYAML` (PyYAML's role taken by ruamel.yaml; pinned PySocks moves to
  `requests[socks]` extra).
- Direct deps trimmed from 30+ flat-frozen pins to 8 lower-bounded ranges:
  `requests[socks]>=2.32, urllib3>=2.2, ruamel.yaml>=0.18, rich>=13.7, cloudflare>=3,
  beautifulsoup4>=4.12, dnspython>=2.6, psutil>=5.9.8`.
- Migrate `from ruamel import yaml` → `from ruamel.yaml import YAML; _yaml = YAML(typ="rt")`
  (the old import was removed in ruamel.yaml 0.18).
- Migrate `cfRecorder.py` from `cloudflare` v2 SDK (`CloudFlare.CloudFlare(...)`) to v3+
  (`from cloudflare import Cloudflare`). New: pass `email="token"` to switch to API-token auth.

### CLIs
- All 10 CLIs now expose `--version` (was: 0/10 before).
- Migrate 5 shell-style scripts (`scripts/{clashGen, connectMe, shadowChecker,
  sslocal2ssURI, ssURI2sslocal}`) into proper Python modules under `proxyUtil/cli/` with
  `def main(argv=None)`. Registered as `[project.scripts]` entry points — works on Windows
  wheels.
- Standardize `main()` signatures from `argv=sys.argv` + `parse_args(argv[1:])` to
  `argv=None` + `parse_args(argv)`.

### Code quality
- Replace `os.path.dirname(__file__)`-based data lookup with `importlib.resources`.
- Narrow 2 bare `except:` clauses in `myUtil.py` (`tagsChanger`, `createVmessConfig`).
- Apply ruff lint+format across the codebase (rules E/F/W/I/UP/B/SIM/RUF). 0 errors.
- Remove duplicate dict key in `dnsUrl.py`.

### Tests
- New `tests/` suite with 46 cases:
  - `test_parsers.py` — proxy URL parsers + round-trips.
  - `test_helpers.py` — pure helpers (`split2Npart`, `mergeMultiDicts`, etc).
  - `test_dns.py` — DNS table shape.
  - `test_cli_smoke.py` — `--version` + `--help` for every entry point (subprocess).
  - `test_version.py` — `__version__` ↔ `importlib.metadata` integrity.

### CI
- New `.github/workflows/test.yml`: runs ruff + pytest on Python 3.10 / 3.11 / 3.12 for every
  push and PR.
- `python-publish.yml` switched from `python -m build` to `uv build`. Still triggers on tag.

### Docs
- New `CLAUDE.md` for AI assistants navigating the repo.

## 0.1.3
- last 0.1.x release; 2023.
