#!/usr/bin/env bash
# CE 4309 - Wazuh demo recovery script
# Run from the project repo after the Wazuh VM reboots.

set -euo pipefail

VM="${WAZUH_VM:-192.168.122.247}"
SSH_USER="${WAZUH_SSH_USER:-wazuhadmin}"
SSH_TARGET="$SSH_USER@$VM"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================="
echo "CE 4309 Wazuh System Fix"
echo "=========================================="

echo "[1/6] Waiting for Wazuh VM SSH..."
for i in {1..20}; do
  if ssh -o ConnectTimeout=5 "$SSH_TARGET" "echo ready" >/dev/null 2>&1; then
    echo "VM is ready"
    break
  fi
  echo "Waiting... ($i/20)"
  sleep 5
done

echo "[2/6] Installing fixed forwarder and service..."
scp "$ROOT_DIR/wazuh-forwarder.py" "$SSH_TARGET:/tmp/wazuh-forwarder.py" >/dev/null
scp "$ROOT_DIR/wazuh-forwarder.service" "$SSH_TARGET:/tmp/wazuh-forwarder.service" >/dev/null
ssh "$SSH_TARGET" "sudo install -m 0755 /tmp/wazuh-forwarder.py /usr/local/bin/wazuh-forwarder.py && sudo install -m 0644 /tmp/wazuh-forwarder.service /etc/systemd/system/wazuh-forwarder.service && sudo systemctl daemon-reload"

echo "[3/6] Applying stable service state..."
ssh "$SSH_TARGET" "sudo systemctl stop wazuh-auto-response 2>/dev/null || true; sudo systemctl start wazuh-dashboard"

echo "[4/6] Resetting forwarder offset for live indexing..."
ssh "$SSH_TARGET" "sudo mkdir -p /var/lib/wazuh-forwarder && echo 0 | sudo tee /var/lib/wazuh-forwarder/offset.txt >/dev/null"

echo "[5/6] Starting forwarder..."
ssh "$SSH_TARGET" "sudo systemctl restart wazuh-forwarder"

echo "[6/6] Verifying services..."
ssh "$SSH_TARGET" "systemctl is-active wazuh-dashboard wazuh-forwarder; curl -sk -u admin:admin https://localhost:9200/_cluster/health"

echo "=========================================="
echo "System Ready"
echo "Dashboard: https://$VM"
echo "Run demo: bash demo.sh"
echo "AI agent: python3 -u tools/ai-soc-agent.py"
echo "=========================================="
