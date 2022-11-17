# proxyUtil

## General info
some proxy tools

## Requirements
- [python3](https://www.python.org/downloads)
- [install requirements packages](https://gist.github.com/mheidari98/8ae29b88bd98f8f59828b0ec112811e7)
- [shadowsocks](https://github.com/shadowsocks/shadowsocks-libev#installation)    
- [v2ray](https://www.v2fly.org/en_US/guide/install.html)
- [xray](https://github.com/XTLS/Xray-core#installation)

## Usage
+ fast checkout live proxy:
  ```bash
  ./v2rayChecker.py -T 50 -f servers.txt
  ```
  or :
  ```bash
  cat servers.txt | ./v2rayChecker.py -T 50 --stdin 
  ```
+ for check shadowsocks proxy in shadowServer.txt with 50 thread and 3sec timeout with specific domain:
  ```bash
  ./shadowChecker.py --domain https://www.google.com --timeout 3  -T 50 -f shadowServer.txt
  ```
+ for check proxy from specific url:
  ```bash
  ./v2rayChecker.py --url 'https://www.site.xyz/servers.txt'
  ```
+ get and check some free proxy:
  ```bash
  ./v2rayChecker.py --free
  ```

---

tip: better to use a fixed IP address instead of fully qualified domain name (FQDN), cuz a FQDN would require a DNS lookup. When the machine does not have a working internet connection, the DNS lookup itself may block for more than a second. ([stackoverflow](https://stackoverflow.com/questions/3764291))  
+ find a current IP address for google.com (on unix) by running :
  ```console
  % dig +noall +answer google.com
  ...
  google.com.     300 IN  A   216.58.192.142
  ```
---

## Task-Lists
- [x] support shadowsocks protocol
- [x] support vmess protocol
- [x] support vless protocol
- [x] support trojan protocol
- [x] support xray-core
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
+ [Proxy performance batch tester based on Shadowsocks(R) and V2Ray](https://github.com/tindy2013/stairspeedtest-reborn)
+ [A simple tool for batch test ss/ssr/v2ray/trojan servers](https://github.com/xxf098/LiteSpeedTest)
* [vmess to json](https://github.com/boypt/vmess2json/wiki/vmess2json)
* [Some examples of uses for V2ray-core](https://github.com/v2fly/v2ray-examples)
* [Some examples of uses for Xray-core](https://github.com/XTLS/Xray-examples)
* [Get Internal and External IP Address](https://gist.github.com/mheidari98/8801d3afcea3c7a27393abc2bdbec17d)
