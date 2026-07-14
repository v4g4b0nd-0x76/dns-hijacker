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
    "*.test.com:192.168.1.1",
]

# the public known resolvers you want to use normally
resolvers = [
    "https://cloudflare-dns.com/dns-query",
    "8.8.8.8:53",
    "1.1.1.1:53",
]
```

**There is a simple LRU cache implemented that there is no need for sending Qname request to resolvers after first resolve**

## TODO 
- [ ] Add TTL to LRU cache 
- [ ] Remove the blocking `println` and replace with tracing
- [ ] Add a resolver discovery service to find public resolvers(might be useful during filtering)
