# Dns Hijacker

Simple DNS hijacker to run on servers or localhost to manage which IPs your system resolves.
Personally used to redirect blacklisted sites to an unknown destination.

## Build

```bash
./scripts/build.sh          # native (GNU Linux or macOS M4)
./scripts/build.sh musl     # static Linux musl
./scripts/build.sh gnu      # Linux GNU
./scripts/build.sh mac      # aarch64-apple-darwin (M4)
make test
```

## Run as a service

See [assets/SERVICES.md](assets/SERVICES.md) for systemd (Linux) and launchd (macOS) install steps.
Unit files live in `assets/dns_hijacker.service` and `assets/com.dns-hijacker.plist`.

## Sample config

```toml
# domain that you want to block/resolve nothing
drop_list = [
    "google.com",
    "*.example.com",
]
# domains that you want to be resolved with your prefered ip(simple solotion for hijacking or layer 4/7 filter bypass)
redirect_list = [
    "google.com:1.1.1.1,2.2.2.2",
    "*.test.com:192.168.1.1",
]

# the public known resolvers you want to use normally
resolvers = [
    "https://cloudflare-dns.com/dns-query",
    "8.8.8.8:53",
    "1.1.1.1:53",
]

# this section is optional and you can skip it 
[resolver_searching]
enable = true # set false if you want to not have it 
resolver_source = [
     "https://public-dns.info/nameservers-all.txt",
     "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
]
refresh_interval = 30
ipv4 = true 
doh = true

[hotreload_conf]
enable = true 
poll_interval_ms = 100


```

**There is a simple LRU cache implemented that there is no need for sending Qname request to resolvers after first resolve**

## TODO 
- [x] Add TTL to LRU cache 
- [x] Remove the blocking `println` and replace with tracing
- [x] Add a resolver discovery service to find public resolvers(might be useful during filtering)
- [x] Hot reload for config
- [x] redirect with multiple ip
- [ ] resolve directly like dig 
- [ ] add google geo ip for redirect google ips
**Idea: give this as a comamnd entry and specify as resolve_conf.toml that define the domain/sni and where it can find ips for it to create a redirect list for the actual ips not DPI dns resolver**
```text
https://www.gstatic.com/ipranges/goog.json
https://www.gstatic.com/ipranges/cloud.json
# using this code written by me for finding google ips 
https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/src/scan_ips.rs
```
- [ ] For uncached domains queue all request and dont resolve multiple time resolve one time and cache them repond all of them with 1 IO reqeust
