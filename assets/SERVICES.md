# Running dns-hijacker as a background service

Install the release binary built with `./scripts/build.sh`, then use the unit below for your OS.

Default listen address is `127.0.0.1:53` (needs privileged bind).

## Linux (systemd)

Required capability: `CAP_NET_BIND_SERVICE` (bind port 53 without full root).

```bash
# 1) Build (example: musl static)
./scripts/build.sh musl

# 2) Install files
sudo useradd --system --home /opt/dns-hijacker --shell /usr/sbin/nologin dns-hijacker || true
sudo mkdir -p /opt/dns-hijacker
sudo cp target/*/release/dns-hijacker /opt/dns-hijacker/dns-hijacker
sudo mkdir /opt/dns-hijacker/logs 
# or native path:
# sudo cp target/release/dns-hijacker /opt/dns-hijacker/dns-hijacker
sudo cp conf.toml /opt/dns-hijacker/
sudo cp assets/dns_hijacker.service /etc/systemd/system/dns-hijacker.service
sudo chown -R dns-hijacker:dns-hijacker /opt/dns-hijacker
sudo chmod 755 /opt/dns-hijacker/dns-hijacker

# 3) Enable + start
sudo systemctl daemon-reload
sudo systemctl enable --now dns-hijacker.service
sudo systemctl status dns-hijacker.service
```

Alternative without a dedicated user (capability on the binary):

```bash
sudo setcap cap_net_bind_service=+ep /opt/dns-hijacker/dns-hijacker
```

Logs:

```bash
journalctl -u dns-hijacker -f
```

## macOS Apple Silicon (M4) — launchd

Port 53 requires a root LaunchDaemon on macOS.

```bash
./scripts/build.sh mac
sudo mkdir -p /opt/dns-hijacker
sudo cp target/aarch64-apple-darwin/release/dns-hijacker /opt/dns-hijacker/
sudo cp conf.toml /opt/dns-hijacker/
sudo cp assets/com.dns-hijacker.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.dns-hijacker.plist
sudo launchctl enable system/com.dns-hijacker
sudo launchctl kickstart -k system/com.dns-hijacker
```

Stop / unload:

```bash
sudo launchctl bootout system/com.dns-hijacker
```

Logs: `/var/log/dns-hijacker.out.log` and `/var/log/dns-hijacker.err.log`.

## Point the OS at the local resolver

- Linux: set DNS to `127.0.0.1` in NetworkManager / systemd-resolved / `/etc/resolv.conf`.
- macOS: System Settings → Network → DNS → `127.0.0.1`.
