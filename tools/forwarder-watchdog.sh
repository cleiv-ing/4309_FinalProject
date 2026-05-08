#!/usr/bin/env bash
# CE 4309 - Forwarder watchdog
# Runs from the NixOS/admin host and recovers common forwarder stalls.

set -euo pipefail

VM="${WAZUH_VM:-192.168.122.247}"
SSH_USER="${WAZUH_SSH_USER:-wazuhadmin}"
SSH_TARGET="$SSH_USER@$VM"

ssh "$SSH_TARGET" <<'EOF'
set -e
ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
OFFSET_FILE="/var/lib/wazuh-forwarder/offset.txt"

ALERTS_SIZE=$(sudo stat -c %s "$ALERTS_FILE" 2>/dev/null || echo 0)
OFFSET=$(sudo cat "$OFFSET_FILE" 2>/dev/null || echo 0)

if [ "$OFFSET" -gt "$ALERTS_SIZE" ] && [ "$ALERTS_SIZE" -gt 0 ]; then
  echo "Resetting stuck forwarder offset: $OFFSET > $ALERTS_SIZE"
  echo 0 | sudo tee "$OFFSET_FILE" >/dev/null
  sudo systemctl restart wazuh-forwarder
fi

if ! systemctl is-active --quiet wazuh-forwarder; then
  echo "Forwarder was stopped; starting it"
  sudo systemctl start wazuh-forwarder
fi

echo "Forwarder watchdog OK"
EOF
