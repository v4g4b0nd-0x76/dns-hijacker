# Running dns-relay as a background service

Install the release binary built with `./scripts/build.sh`, then use the unit below for your OS.

Default listen address is `127.0.0.1:53` (needs privileged bind).

## Linux (systemd)

Required capability: `CAP_NET_BIND_SERVICE` (bind port 53 without full root).

```bash
# 1) Build (example: musl static)
./scripts/build.sh musl

# 2) Install files
sudo useradd --system --home /opt/dns-relay --shell /usr/sbin/nologin dns-relay || true
sudo mkdir -p /opt/dns-relay
sudo cp target/*/release/dns-relay /opt/dns-relay/dns-relay
sudo mkdir /opt/dns-relay/logs 
# or native path:
# sudo cp target/release/dns-relay /opt/dns-relay/dns-relay
sudo cp conf.toml /opt/dns-relay/
sudo cp assets/dns_relay.service /etc/systemd/system/dns-relay.service
sudo chown -R dns-relay:dns-relay /opt/dns-relay
sudo chmod 755 /opt/dns-relay/dns-relay
# 3) Allow the service user to reassert DNS via systemd-resolved without root.
#    Required for netguard's VPN DNS-reassertion feature; skip this only if
#    you don't need that (e.g. always-on VPN protection isn't a concern).
sudo cp assets/49-dns-relay-resolved.rules /etc/polkit-1/rules.d/


# 3) Enable + start
sudo systemctl daemon-reload
sudo systemctl enable --now dns-relay.service
sudo systemctl status dns-relay.service
```

Alternative without a dedicated user (capability on the binary):

```bash
sudo setcap cap_net_bind_service=+ep /opt/dns-relay/dns-relay
```

Logs:

```bash
journalctl -u dns-relay -f
```

## macOS Apple Silicon (M4) — launchd

Port 53 requires a root LaunchDaemon on macOS.

```bash
./scripts/build.sh mac
sudo mkdir -p /opt/dns-relay
sudo cp target/aarch64-apple-darwin/release/dns-relay /opt/dns-relay/
sudo cp conf.toml /opt/dns-relay/
sudo cp assets/com.dns-relay.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.dns-relay.plist
sudo launchctl enable system/com.dns-relay
sudo launchctl kickstart -k system/com.dns-relay
```

Stop / unload:

```bash
sudo launchctl bootout system/com.dns-relay
```

Logs: `/var/log/dns-relay.out.log` and `/var/log/dns-relay.err.log`.

## Point the OS at the local resolver

- Linux: set DNS to `127.0.0.1` in NetworkManager / systemd-resolved / `/etc/resolv.conf`.
- macOS: System Settings → Network → DNS → `127.0.0.1`.
