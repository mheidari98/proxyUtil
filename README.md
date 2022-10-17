# proxyUtil

## General info
some proxy tools

## Requirements
- [python3](https://www.python.org/downloads)
- [install requirements packages](https://gist.github.com/mheidari98/8ae29b88bd98f8f59828b0ec112811e7)
- [shadowsocks client](https://github.com/shadowsocks/shadowsocks-libev#installation)    
- [v2ray](https://www.v2fly.org/en_US/guide/install.html)

## Usage
  for check shadowsocks proxy in server.txt with 50 thread:
  ```bash
  ./shadowChecker.py --domain https://www.google.com --timeout 3 --lport 1080 -T 50 server.txt
  ```
  for check vmess proxy in server.txt:
  ```bash
  ./v2rayChecker.py --domain https://www.google.com --timeout 3 --lport 1080 server.txt
  ```

---

## Task-Lists
- [x] support shadowsocks protocol
- [x] support vmess protocol
- [ ] support vless protocol
- [ ] support trojan protocol
- [ ] add more free server proxy
- [x] threading support
- [ ] complete Document

---

## Related Links
* [Using Shadowsocks with Command Line Tools](https://github.com/shadowsocks/shadowsocks/wiki/Using-Shadowsocks-with-Command-Line-Tools)
  ```bash
  # for install proxychains
  sudo apt-get install proxychains
  # proxify bash
  proxychains bash
  ```
* [vmess to json](https://github.com/boypt/vmess2json/wiki/vmess2json)
* [Get Internal and External IP Address](https://gist.github.com/mheidari98/8801d3afcea3c7a27393abc2bdbec17d)
