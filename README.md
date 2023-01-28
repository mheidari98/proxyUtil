# proxyUtil

## General info
some proxy tools

## Requirements
- [python 3](https://www.python.org/downloads)
- [install shadowsocks](https://github.com/shadowsocks/shadowsocks-libev#installation)
  ```console
  sudo apt install shadowsocks-libev
  ```
- [install v2ray](https://www.v2fly.org/en_US/guide/install.html)
  ```console
  sudo bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
  ```
- [install xray](https://github.com/XTLS/Xray-core#installation)
  ```console
  sudo bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  ```

## Installation
  ```console
  pip install --upgrade git+https://github.com/mheidari98/proxyUtil@main
  ```

## Uninstall
  ```console
  pip uninstall proxyUtil
  ```

## Usage
  + #### check [wiki](https://github.com/mheidari98/proxyUtil/wiki)

---

## Tools
- [x] **connectMe** : Simple cli proxy client for shadowsocks, vmess, vless, trojan
- [x] **v2rayChecker** : Simple shadowsocks, vmess, vless, trojan checker with v2ray/xray core
- [x] **shadowChecker** : Simple shadowsocks proxy checker with shadowsocks-libev
- [x] **dnsChecker** : Simple DNS over UDP, DNS over TLS and DNS over HTTPS Checker
- [x] **clashGen** : Convert vmess, vless, trojan, shadowsocks,... proxy to Clash Config
- [x] **cdnGen** : Generating vmess url with cloudflare or arvan CDN IPs as address and our domain as host or sni for tls
- [x] **ssURI2sslocal** : shadowsocks URI to ss-local command
- [x] **sslocal2ssURI** : ss-local command to shadowsocks URI


## Status
Project is: _in progress_

## License
[MIT](https://choosealicense.com/licenses/mit)

## Contact
Created by [@mheidari98](https://github.com/mheidari98)

## Support
If you like this project, please consider supporting it by donating to the following bitcoin address:



