# dns-hijacker

A small DNS server, written in Rust, meant to run on a local machine or a server, that lets you control how specific domains resolve. It was built for personal use — mainly redirecting or dropping specific domains — and is intentionally simple rather than a full-featured DNS resolver.

This isn't a polished product; it's a personal tool shared as-is. The notes below describe what it does and how to configure it, based on the project's README and the relay feature discussed during its development.

## What it does

It binds to UDP port 53 and, for each incoming query:

1. Checks a **drop list** — if the domain matches, it replies with NXDOMAIN instead of resolving anything.
2. Checks a **redirect list** — if the domain matches a pattern, it replies with a chosen IP address directly, skipping real resolution entirely.
3. Checks an in-memory **LRU cache** — if a recent answer for this exact query is cached, it's served immediately (with the transaction ID rewritten to match the new request), avoiding a repeat lookup.
4. Otherwise, it resolves the domain either through a normal upstream resolver (DoH endpoint or plain UDP resolver) or, if configured, through a **relay** — an encrypted tunnel to a Cloudflare Worker that performs the actual DNS-over-HTTPS lookup on your behalf.

The drop/redirect lists exist for basic personal filtering or DNS-based hijacking of specific domains. The relay path exists as a way to get real answers back even when a local network or ISP is tampering with DNS traffic on the wire, since the query never appears as plaintext DNS at any point.

## Build

```bash
./scripts/build.sh          # native (GNU Linux or macOS M4)
./scripts/build.sh musl     # static Linux musl
./scripts/build.sh gnu      # Linux GNU
./scripts/build.sh mac      # aarch64-apple-darwin (M4)
make test
```

Since it needs to bind to port 53, it needs to run with elevated privileges. Either run it with `sudo`, or grant the capability directly so it doesn't need to run as root:

```bash
sudo setcap cap_net_bind_service=+ep PATH_TO_BINARY
```

## Running as a service

There are systemd (Linux) and launchd (macOS) setup notes in `assets/SERVICES.md`, with unit files at `assets/dns_hijacker.service` and `assets/com.dns-hijacker.plist`.

## Config format

The base config controls the drop list, redirect list, and which upstream resolvers to use:

```toml
# domains you want to block (resolve to nothing / NXDOMAIN)
drop_list = [
    "google.com",
    "*.example.com",
]

# domains you want resolved to a specific IP instead of their real answer
redirect_list = [
    "*.test.com:192.168.1.1",
]

# public resolvers to use for everything else
resolvers = [
    "https://cloudflare-dns.com/dns-query",
    "8.8.8.8:53",
    "1.1.1.1:53",
]
```

Both `drop_list` and `redirect_list` support wildcard patterns (`*.example.com` matches both `example.com` and any subdomain). `resolvers` can mix DoH URLs and plain `ip:port` UDP resolvers.

There's a built-in LRU cache, so once a name has been resolved once, repeat queries for it are served from memory rather than re-querying a resolver each time.
### resolver searching
If you want to fetch resolvers from open source sources like github and test them concurrently set this config
```toml 
[resolver_searching]
enable = false
resolver_source = [
 "https://public-dns.info/nameservers-all.txt",
 "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
]
refresh_interval = 30
ipv4 = true
doh = true


```

### Relay config

If you want DNS queries to go through an encrypted relay (a Cloudflare Worker acting as a DoH proxy) instead of querying resolvers directly — useful if something on the network path is tampering with or blocking plain DNS — there's a `relay_conf` section:

```toml
[relay_conf]
enable = true

[[relay_conf.relay_instances]]
relay_key = "<base64 AES-256-GCM key>"
relay_url = "https://your-worker.your-subdomain.workers.dev/"
```

`[[relay_conf.relay_instances]]` can be repeated to configure more than one relay worker; the tool round-robins across them. Each query is AES-256-GCM encrypted, sent as a plain HTTPS POST to the worker, which decrypts it, performs the actual DoH lookup, encrypts the reply, and sends it back — so the traffic looks like an ordinary HTTPS API call rather than DNS traffic.

Relay keys are generated locally (never sent anywhere), and the same key needs to be set as a secret on the Worker side so it can decrypt what the client sends.

## CLI

Aside from running the server, there are a couple of standalone commands for setup and troubleshooting — generating a relay key, and resolving a single domain (optionally through the relay) without running the full server. Exact flag names may vary by version; check `--help` on your build for the authoritative list.

## A note on scope

This is a simple, personal-use tool, not a hardened production resolver — there's no built-in DNSSEC validation, and the filtering (drop/redirect lists) is pattern-based rather than anything more sophisticated. The README's own TODO list reflects this: replacing blocking `println!` calls with proper tracing, and adding resolver auto-discovery, are both still open.
