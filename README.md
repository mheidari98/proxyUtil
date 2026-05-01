# proxyUtil

CLI suite for shadowsocks / vmess / vless / trojan and DNS utilities.
Current version: **0.4.0**. Python: **>=3.10**. License: MIT.

## Requirements
- [python 3.10+](https://www.python.org/downloads)
- (optional, for `connectMe` / `shadowChecker`) [shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev#installation)
  ```console
  sudo apt install shadowsocks-libev
  ```
- (optional, for `connectMe` / `v2rayChecker`) [v2ray](https://www.v2fly.org/en_US/guide/install.html)
  ```console
  sudo bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
  ```
- (optional, for `connectMe` / `v2rayChecker`) [xray](https://github.com/XTLS/Xray-core#installation)
  ```console
  sudo bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  ```
- (optional, for `connectMe` / `v2rayChecker`, validates hysteria/hysteria2/tuic/anytls/etc.)
  [sing-box](https://sing-box.sagernet.org/installation/) — `connectMe` and `v2rayChecker`
  will offer to download a release binary on first run if the binary is not on `PATH`.

## Install
```console
pip install --upgrade git+https://github.com/mheidari98/proxyUtil@main
```

Or with [uv](https://docs.astral.sh/uv/):
```console
uv tool install git+https://github.com/mheidari98/proxyUtil@main
```

## Uninstall
```console
pip uninstall proxyUtil
```

## Tools
All commands accept `--version` and `--help`.

- [**connectMe**](https://github.com/mheidari98/proxyUtil/wiki/connectMe) — simple CLI proxy client for shadowsocks/vmess/vless/trojan
- [**v2rayChecker**](https://github.com/mheidari98/proxyUtil/wiki/v2rayChecker) — vmess/vless/trojan/ss checker driven by v2ray/xray
- [**shadowChecker**](https://github.com/mheidari98/proxyUtil/wiki/shadowChecker) — shadowsocks-libev based ss checker
- [**dnsChecker**](https://github.com/mheidari98/proxyUtil/wiki/dnsChecker) — DNS over UDP / DoT / DoH probe
- [**clashGen**](https://github.com/mheidari98/proxyUtil/wiki/clashGen) — convert proxy URLs to a Clash config
- [**cdnGen**](https://github.com/mheidari98/proxyUtil/wiki/cdnGen) — rewrite vmess/vless/trojan to ride Cloudflare/Arvan CDN IPs
- [**cfRecorder**](https://github.com/mheidari98/proxyUtil/wiki/cfRecorder) — sync Cloudflare DNS A-records (uses `cloudflare>=3` SDK)
- [**ipExtractor**](https://github.com/mheidari98/proxyUtil/wiki/ipExtractor) — extract IPs from a list of proxy URLs
- [**ssURI2sslocal**](https://github.com/mheidari98/proxyUtil/wiki/ssURI2sslocal) — `ss://` URI → `ss-local` cmdline
- [**sslocal2ssURI**](https://github.com/mheidari98/proxyUtil/wiki/sslocal2ssURI) — `ss-local` cmdline → `ss://` URI

## Development
Repo uses [uv](https://docs.astral.sh/uv/), [hatchling](https://hatch.pypa.io/latest/),
[ruff](https://docs.astral.sh/ruff/), and [pytest](https://docs.pytest.org/).

```console
uv sync --all-extras                     # install editable + dev deps
uv run pytest -v                         # run tests
uv run pytest --cov=proxyUtil            # coverage
uv run ruff check . --fix                # lint+autofix
uv run ruff format .                     # format
uv run basedpyright proxyUtil            # type check
uv build                                 # build sdist + wheel into dist/
pre-commit install                       # (optional) install git hooks
```

CI runs ruff + basedpyright + pytest on Python 3.10 / 3.11 / 3.12 for every push and PR.

## Release
1. Bump `proxyUtil/__version__.py`.
2. Update `CHANGES.md`.
3. `git tag vX.Y.Z && git push --tags` — `python-publish.yml` builds with `uv build` and
   publishes to TestPyPI then PyPI. The workflow can also be invoked manually via
   `workflow_dispatch` (target = `test` or `prod`).

## Status
_in progress_

## License
[MIT](https://choosealicense.com/licenses/mit)

## Contact
Created by [@mheidari98](https://github.com/mheidari98).

## Disclaimer
* This project is meant for personal and educational uses only.
* Please follow relevant laws and regulations when using this project.
* The project owner is not responsible or liable in any manner for the use of the content.

<!--
## Total Count

![Alt](https://repobeats.axiom.co/api/embed/0289398971e985e98985882b31d74a3171ac053d.svg "Repobeats analytics image")

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=mheidari98/proxyUtil&type=Date)](https://star-history.com/#mheidari98/proxyUtil&Date)

-->
