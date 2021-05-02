# HSD AXFR

This an experimental plugin that implements DNS zone transfer protocol (AXFR) [RFC5936](https://tools.ietf.org/html/rfc5936) for [hsd](https://github.com/handshake-org/hsd)


### Example

```
dig @127.0.0.1 -p 5349 . axfr > root.zone
```


That's it! root.zone should now have the complete handshake root zone (merged with ICANN names).


## Install

For now the plugin must be inside hsd directory

```
$ git clone https://github.com/handshake-org/hsd && cd hsd 
hsd$ git clone https://github.com/buffrr/hsd-axfr axfr

npm install --production
$ hsd --plugins=$(pwd)/axfr
```


### Parameters

- `--axfr-prefer-icann`: Prefers ICANN TLDs in case of a name collision
- `--axfr-no-icann`: Dump Handshake names only.
- `--axfr-icann-servers`: Set AXFR Servers used to load the ICANN root zone
- `--axfr-allow-ips`: Set IP addresses permitted to request a zone transfer

### Name collisions

Since the default behavior in hsd is falling back to ICANN, the plugin also does the same. You can use `--axfr-prefer-icann` to change this behavior.

You can see name collisions in the logs. Example:
```
[warning] (axfr) name collision for xn--cckwcxetd. (prefer icann: false)
```

### ICANN AXFR Servers

The following servers are used by default for AXFR:

```
b.root-servers.net
c.root-servers.net
f.root-servers.net
```

You can change these by setting `--axfr-icann-servers='<server1 server2 ...>'` 

### Allowed IPs

You should keep hsd as an internal server. By default, AXFR queries are only allowed from lookpback address.

The `--axfr-allow-ips='<ip1 ip2 ...>'` option specifies which ip addresses are allowed to request a transfer.

### License

MIT
