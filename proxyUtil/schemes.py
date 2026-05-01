"""Scheme constants and the ordered list used by URL discovery."""

from __future__ import annotations

__all__ = [
    "FRAGMENT_TAGGED",
    "anytls_scheme",
    "hy2_scheme",
    "hysteria2_scheme",
    "hysteria_scheme",
    "juicity_scheme",
    "naive_scheme",
    "proxyScheme",
    "shadowtls_scheme",
    "ss_scheme",
    "ssh_scheme",
    "ssr_scheme",
    "trojan_scheme",
    "tuic_scheme",
    "vless_scheme",
    "vmess_scheme",
    "wireguard_scheme",
]

FRAGMENT_TAGGED = frozenset({
    "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic",
    "anytls", "shadowtls", "ssh", "wireguard", "juicity",
})

ss_scheme = "ss://"
ssr_scheme = "ssr://"
vmess_scheme = "vmess://"
vless_scheme = "vless://"
trojan_scheme = "trojan://"
hysteria_scheme = "hysteria://"
hysteria2_scheme = "hysteria2://"
hy2_scheme = "hy2://"
tuic_scheme = "tuic://"
anytls_scheme = "anytls://"
shadowtls_scheme = "shadowtls://"
naive_scheme = "naive+https://"
ssh_scheme = "ssh://"
wireguard_scheme = "wireguard://"
juicity_scheme = "juicity://"

proxyScheme = [
    vmess_scheme, vless_scheme, trojan_scheme, ssr_scheme, ss_scheme,
    hysteria2_scheme, hy2_scheme, hysteria_scheme, tuic_scheme,
    anytls_scheme, shadowtls_scheme, naive_scheme, ssh_scheme,
    wireguard_scheme, juicity_scheme,
]
