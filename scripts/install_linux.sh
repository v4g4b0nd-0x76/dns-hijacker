#!/bin/bash
set -euo pipefail

LOG_FILE="/tmp/dns-relay-install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
set -x

echo "=== dns-relay install started at $(date -Iseconds) ==="
echo "Logging to $LOG_FILE"

sudo useradd --system --home /opt/dns-relay --shell /usr/sbin/nologin dns-relay || true
sudo mkdir -p /opt/dns-relay
sudo cp target/*/release/dns-relay /opt/dns-relay/dns-relay
sudo cp conf.toml /opt/dns-relay/
sudo cp assets/dns_relay.service /etc/systemd/system/dns-relay.service
sudo mkdir -p /opt/dns-relay/logs
sudo chown -R dns-relay:dns-relay /opt/dns-relay
sudo chmod 755 /opt/dns-relay/dns-relay
sudo systemctl daemon-reload
sudo systemctl enable --now dns-relay.service
sudo systemctl status dns-relay.service

echo "=== dns-relay install finished at $(date -Iseconds) ==="
echo "Full log available at $LOG_FILE"
