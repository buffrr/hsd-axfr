# HSD AXFR

This an experimental plugin that implements DNS zone transfer protocol (AXFR) [RFC5936](https://tools.ietf.org/html/rfc5936) for [hsd](https://github.com/handshake-org/hsd)


## Install

For now the plugin must be inside hsd directory

```
git clone https://github.com/handshake-org/hsd && cd hsd 
git clone https://github.com/buffrr/hsd-axfr axfr
git apply axfr/rinfo.patch

npm install 
./bin/hsd --plugins=$(pwd)/axfr --axfr-allow-ips=127.0.0.1
```


## Usage

```
dig @127.0.0.1 -p 5349 . axfr > root.zone
```

That's it! root.zone should now have the complete root zone. 

The `--axfr-allow-ips=<ip1 ip2 ...>` option specifies which ip addresses are allowed to request a transfer.

The plugin sends multiple dns messages with about 1500 rrs per message. You can set `--axfr-chunk-length=<default 1500>`  to change that (chunk length is the number of resource records not octets!). Keep in mind that max message size over tcp is 65535 octets.  
