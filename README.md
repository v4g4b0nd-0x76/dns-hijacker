# dns-hijacker

A small DNS server, written in Rust, meant to run on a local machine or a server, that lets you control how specific domains resolve. It was built for personal use — mainly redirecting or dropping specific domains — and is intentionally simple rather than a full-featured DNS resolver.

This isn't a polished product; it's a personal tool shared as-is. The notes below describe what it does and how to configure it, based on the project's README and the relay feature discussed during its development.

## What it does

It binds to UDP port 53 and, for each incoming query:

1. Checks a **drop list** — if the domain matches, it replies with NXDOMAIN instead of resolving anything.
2. Checks a **redirect list** — if the domain matches a pattern, it replies with a chosen IP address directly, skipping real resolution entirely.
3. Checks an in-memory **LRU cache** — if a recent answer for this exact query is cached, it's served immediately (with the transaction ID rewritten to match the new request), avoiding a repeat lookup.
4. Otherwise, it resolves the domain either through a normal upstream resolver (DoH endpoint or plain UDP resolver) or, if configured, through a **relay** — an encrypted tunnel that performs the actual DNS-over-HTTPS lookup on your behalf, described below.

The drop/redirect lists exist for basic personal filtering or DNS-based hijacking of specific domains. The relay path exists as a way to get real answers back even when a local network or ISP is tampering with or blocking DNS traffic on the wire, since the query never appears as plaintext DNS at any point.

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

### Resolver searching

If you want to fetch resolvers from open-source lists and test them concurrently:

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

## Relay config

If you want DNS queries to go through an encrypted relay instead of querying resolvers directly — useful if something on the network path is tampering with or blocking plain DNS — there's a `relay_conf` section. Each relay instance is AES-256-GCM encrypted end-to-end between the Rust client and the final resolver, so on the wire it just looks like an ordinary HTTPS POST, not DNS traffic. There are two supported ways to reach a relay instance: **direct** (straight to a Cloudflare Worker) and **google_chained** (routed through a Google Apps Script hop first, in front of the same kind of Worker).

```toml
[relay_conf]
enable = true

[[relay_conf.relay_instances]]
relay_key = "<base64 AES-256-GCM key>"
relay_url = "https://your-worker.your-subdomain.workers.dev/"
transport = "direct"

[[relay_conf.relay_instances]]
relay_key = "<base64 AES-256-GCM key>"
relay_url = "https://script.google.com/macros/s/AKfycbXXXXXXXXXXXXXXXX/exec"
transport = "google_chained"
```

`[[relay_conf.relay_instances]]` can be repeated as many times as you like, mixing transports freely; the tool round-robins across all configured instances. `transport` defaults to `"direct"` if omitted, so existing single-Worker configs don't need to change.

### Why two transports

A direct Cloudflare Worker relay is simple and fast, but in some networks (this was built with Iranian ISP-level filtering in mind) Cloudflare's own IP ranges get blocked outright while Google's generally don't. The `google_chained` transport exists for that case: the same encrypted DNS packet gets wrapped in one more hop — a small Google Apps Script web app — before reaching the Cloudflare Worker. Apps Script runs on Google's own infrastructure, not your network, so if Google is reachable but Cloudflare isn't, this extra hop gets you there anyway.

Both transports use the _same_ `relay_key` semantics: it's always the AES-256-GCM key shared between the Rust client and the Cloudflare Worker that actually performs the DNS-over-HTTPS lookup. The Google Apps Script hop, when used, never sees this key and can't decrypt anything — it only ever handles already-encrypted, base64-wrapped ciphertext, plus an opaque cache tag (an HMAC of the domain, derived from the same key) that lets it cache repeat lookups without ever learning what domain was actually queried.

### Setting up a Cloudflare Worker (direct transport)

1. Generate a relay key locally (never sent anywhere): the tool's key-generation command prints a base64 AES-256-GCM key.
2. Deploy a Worker that decrypts incoming requests with this key, forwards the decrypted DNS query to a DoH endpoint (e.g. `https://cloudflare-dns.com/dns-query`), and re-encrypts the reply with the same key before returning it.
3. Store the key as a Worker **secret** (`wrangler secret put RELAY_KEY`), not hardcoded in the Worker's source.
4. Put the same key and the Worker's URL into `conf.toml` as a `relay_instances` entry with `transport = "direct"`.

### Setting up the Google Apps Script hop (google_chained transport)

1. In [script.google.com](https://script.google.com), create a new project. It needs a `doPost` handler that: reads a JSON body containing the base64-encoded encrypted packet and a cache-key tag, checks its own cache for that tag, and if not cached, forwards the decoded bytes to your Cloudflare Worker's URL via `UrlFetchApp`, then caches and returns the Worker's (still-encrypted) response.
2. Store the actual Cloudflare Worker URL in the project's **Script Properties** (`Project Settings → Script Properties`), not hardcoded in the script and not sent by the client — this keeps the deployment from being usable as an open relay to arbitrary destinations.
3. Deploy it as a **Web app** (`Deploy → New deployment → Web app`), with **Execute as: Me** and **Who has access: Anyone** — the "Anyone" setting is required since the Rust client calls it anonymously, with no Google login.
4. Copy the resulting `.../exec` URL (this includes the deployment ID — there's no separate place to configure that) into `conf.toml` as `relay_url`, alongside the _same_ `relay_key` used by the underlying Worker, with `transport = "google_chained"`.
5. If you edit the script later, redeploying as a **new version of the existing deployment** (rather than a brand-new deployment) keeps the same `.../exec` URL, so `conf.toml` doesn't need updating each time.

### Metrics 
You can see the behaviour of resolver using metrics option in configs by enabling it and setting the report type form terminal `LOG` or `/metrics` http endpoint
```toml
[metric_conf]
enable = true
report_type = "log"
report_interval = 30 # number of second for each log
```

**Note: in console mode for not logging when there is no activity a new log will be shown whenever there is difference between request count from previous interval**

### Limits worth knowing

Google Apps Script has real quotas (roughly 20,000 outbound fetches/day on a free account, a several-minute execution budget per call, and no built-in high-concurrency handling), and adds noticeably more latency per request than a Cloudflare Worker alone. The built-in per-hop caching helps offset this for repeat lookups, but it's not a drop-in replacement for Cloudflare's own scaling — treat it as a fallback path for when Cloudflare itself is unreachable, not a primary one.

## CLI

Aside from running the server, there are a couple of standalone commands for setup and troubleshooting — generating a relay key, and resolving a single domain (optionally through a relay) without running the full server. Exact flag names may vary by version; check `--help` on your build for the authoritative list.
