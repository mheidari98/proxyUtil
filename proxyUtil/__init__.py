"""proxyUtil — CLI suite for shadowsocks / vmess / vless / trojan / DNS utilities.

Public surface is the version string. Library modules with explicit ``__all__``:
``parsers`` (URL parsers), ``uri`` (URL builders), ``schemes`` (scheme constants),
``xray`` and ``singbox`` (per-core config builders), ``cores`` (registry), ``net``
(network-side-effect helpers), ``os_glue`` (process / OS), ``shadowsocks``
(ss-libev cmdline), ``utils`` (primitives), ``dnsUtil`` / ``dnsUrl`` /
``logFormatter``.
"""

from .__version__ import __version__

__all__ = ["__version__"]
