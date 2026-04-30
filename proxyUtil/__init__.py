"""proxyUtil — CLI suite for shadowsocks / vmess / vless / trojan / DNS utilities.

The package public surface is intentionally narrow: the version string. Submodules
(``proxyUtil.myUtil``, ``proxyUtil.dnsUtil``, ``proxyUtil.dnsUrl``, ``proxyUtil.network``,
``proxyUtil.logFormatter``) expose their own ``__all__`` and should be imported explicitly.
"""

from .__version__ import __version__

__all__ = ["__version__"]
