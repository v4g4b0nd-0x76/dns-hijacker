#!/bin/bash
set -euo pipefail

LOG_FILE="/tmp/dns-hijacker-install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
set -x

echo "=== dns-hijacker install started at $(date -Iseconds) ==="
echo "Logging to $LOG_FILE"

sudo useradd --system --home /opt/dns-hijacker --shell /usr/sbin/nologin dns-hijacker || true
sudo mkdir -p /opt/dns-hijacker
sudo cp target/*/release/dns-hijacker /opt/dns-hijacker/dns-hijacker
sudo cp conf.toml /opt/dns-hijacker/
sudo cp assets/dns_hijacker.service /etc/systemd/system/dns-hijacker.service
sudo mkdir -p /opt/dns-hijacker/logs
sudo chown -R dns-hijacker:dns-hijacker /opt/dns-hijacker
sudo chmod 755 /opt/dns-hijacker/dns-hijacker
sudo systemctl daemon-reload
sudo systemctl enable --now dns-hijacker.service
sudo systemctl status dns-hijacker.service

echo "=== dns-hijacker install finished at $(date -Iseconds) ==="
echo "Full log available at $LOG_FILE"
