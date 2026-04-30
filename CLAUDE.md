# CLAUDE.md — guide for AI agents working in this repo

## Project

`proxyUtil` is a CLI suite for shadowsocks / vmess / vless / trojan / DNS utilities, distributed
on PyPI. Current version: **0.2.0**. Python: **>=3.10**. License: MIT. Entry point:
`pyproject.toml` (hatchling backend).

## Layout

```
proxyUtil/
  __init__.py        Public API: re-exports myUtil, logFormatter, dnsUrl, dnsUtil
  __version__.py     SOURCE OF TRUTH for version (hatch reads this; bump here only)
  myUtil.py          Core: ~50 utils — proxy URL parsers, config builders, system glue
  dnsUrl.py          Static tables: Do53/DoT/DoH endpoint catalogs
  dnsUtil.py         DNS over UDP/TLS/HTTPS resolvers, IP filter helpers
  logFormatter.py    Coloured logging.Formatter
  cdnGen.py          CLI: rewrite vmess/vless/trojan with CDN IPs as address
  cfRecorder.py      CLI: Cloudflare DNS A-record sync (uses cloudflare>=3 SDK)
  dnsChecker.py      CLI: probe DNS resolvers, render rich.Table
  ipExtractor.py     CLI: extract IPs from a list of proxy URLs
  v2rayChecker.py    CLI: parallel proxy liveness checker, needs xray/v2ray binary
  network.py         Network-side-effect helpers (ScrapURL, downloadZray) — isolated
                     so callers know which utilities hit live HTTP at call time
  _common.py         Internal helper: add_version_arg(parser) for all 10 CLIs
  data/
    Clash-Template.yaml  packaged via importlib.resources
  cli/                  Newer CLIs migrated from old scripts/ folder
    clashGen.py         CLI: builds Clash YAML config (needs `subconverter` docker)
    connectMe.py        CLI: simple ss/v2ray/trojan client launcher
    shadowChecker.py    CLI: parallel ss-libev liveness checker
    sslocal2ssURI.py    CLI: ss-local cmdline → ss:// URI
    ssURI2sslocal.py    CLI: ss:// URI → ss-local cmdline
tests/                pytest unit + CLI smoke (46 cases)
.github/workflows/    test.yml (matrix 3.10/3.11/3.12) + python-publish.yml (on tag)
pyproject.toml        hatchling, [project.scripts]=10 CLIs, ruff, pytest config
.python-version       3.11 (dev env pin only; floor is 3.10)
uv.lock               committed; reproducible deps
```

## Run / dev commands

```bash
uv sync --all-extras                 # install editable + dev deps
uv run pytest -v                     # run tests
uv run pytest --cov=proxyUtil        # coverage
uv run ruff check . --fix            # lint+autofix
uv run ruff format .                 # format
uv run basedpyright proxyUtil        # type check
uv build                             # build sdist + wheel into dist/
pre-commit install                   # (optional) git hooks
uv run cdnGen --help                 # any of the 10 CLIs
uv run cdnGen --version              # prints "cdnGen 0.2.0"
```

The 10 CLIs: `cdnGen, dnsChecker, cfRecorder, ipExtractor, v2rayChecker, clashGen, connectMe,
shadowChecker, sslocal2ssURI, ssURI2sslocal`. All accept `--version` and `--help`.

## Conventions

- **Version source-of-truth**: `proxyUtil/__version__.py:__version__`. Hatch reads it. Bump there only.
- **CLI signature**: every CLI module exposes `def main(argv=None)` and parses `argv` via
  `parser.parse_args(argv)`. Always add `parser.add_argument("--version", action="version",
  version=f"%(prog)s {__version__}")` before any positional argument.
- **Package data**: load via `importlib.resources.files("proxyUtil") / "data" / "X"` — never
  `os.path.dirname(__file__)`. Pre-resolved as `CLASH_SAMPLE_PATH` in `myUtil.py`.
- **YAML**: use `from ruamel.yaml import YAML; _yaml = YAML(typ="rt")`. Never `from ruamel
  import yaml` (removed in ruamel.yaml 0.18). For non-roundtrip needs, instantiate
  `YAML(typ="safe")`.
- **Cloudflare SDK**: v3+ client = `from cloudflare import Cloudflare, APIError`. Methods are
  `cf.zones.list`, `cf.dns.records.list/create/delete/update`, `cf.zones.settings.get`.
  Records are pydantic objects (attribute access, not `[...]`).
- **No wildcard imports anywhere.** Every submodule defines `__all__`; CLIs import the
  specific names they need. The package surface re-exposes only `__version__`.
- **Lint config**: ruff is the single tool; line-length 100; rules `E F W I UP B SIM RUF`.
  No per-file `F403/F405` ignores — wildcard imports are not allowed.
- **Type checking**: `basedpyright` (standard mode) is wired into CI. Some legacy
  pre-existing patterns (regex `match.group()` without null check, urllib attribute access,
  ruamel YAML stub gaps) are silenced via per-rule ignores in `pyproject.toml`.

## Pitfalls

- `downloadZray` and `ScrapURL` (in `proxyUtil.network`) hit external URLs — never call from
  tests. Mark any future test that exercises them with `@pytest.mark.network`. Importing the
  `network` module itself is fine; calling those functions is what triggers I/O.
- `cfRecorder` requires real Cloudflare credentials. The CLI accepts the literal email value
  `"token"` to switch to API-token auth (passes `api_token=...` instead of `api_email/api_key`).
- `from .myUtil import *` in `proxyUtil/__init__.py` re-exports module-level names *including*
  imported modules (`random`, `requests`, etc). Some legacy CLIs rely on this — Pyright will
  warn but it works at runtime.
- `myUtil.py` has known Pyright noise (regex `match.group()` without null check, `urllib.parse`
  attribute access). These are pre-existing patterns — out of scope to fix here.
- `connectMe` and `v2rayChecker` shell out via `subprocess.Popen([cmd], shell=True)` — mild
  security smell, kept for compatibility with the original behavior.

## Release flow

1. Edit `proxyUtil/__version__.py` (`__version__ = "X.Y.Z"`).
2. Update `CHANGES.md`.
3. `git tag vX.Y.Z && git push --tags` → GitHub Actions runs `python-publish.yml` which calls
   `uv build` and pushes to TestPyPI then PyPI.
4. Tag-based publish; non-tag pushes never publish.

## Test guide for AI agents

- Pure parsers (`parse_ss`, `parse_ss_withPlugin`, `parse_ssr`, `parseVless`, `parseTrojan`,
  `Create_ss_url*`) → unit tests in `tests/test_parsers.py`. Use the fixtures in `conftest.py`.
- CLI smoke tests run subprocess against the installed entry points; they auto-skip if the
  package isn't installed in the active venv. Keep them parametrized over the `CLI_NAMES` list.
- DNS table tests assert structure not content; if `dnsUrl.py` adds new entries the tests
  shouldn't need updating.
- `test_version.py` is the canary for hatch + setuptools-metadata drift. If
  `importlib.metadata.version` doesn't match `proxyUtil.__version__` the install is stale —
  run `uv sync --reinstall-package proxyUtil`.

## Known follow-ups (not in 0.2.0)

- Add proper type annotations to `myUtil.py` regex/parse helpers so basedpyright can drop
  the per-rule ignores currently set in `pyproject.toml`.
- Consider gating `downloadZray` behind an env flag rather than a docstring warning.
