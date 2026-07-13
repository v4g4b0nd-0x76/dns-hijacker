# Dns Hijacker

Simple DNS hijacker to run on servers or localhost to manage which IPs your system resolves.
Personally used to redirect blacklisted sites to an unknown destination.

## Build (size-optimized)

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

