# Changes

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
