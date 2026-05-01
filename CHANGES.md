# Changes

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
