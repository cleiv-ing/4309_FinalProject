#!/bin/bash
# CE 4309 Final Project - Demo Script
# 
# Architecture:
#   Attacker (NixOS) -> Windows VM (Flask app) -> Wazuh Manager (detection) -> OpenSearch + Dashboard
#
# IMPORTANT: Dashboard must be started AFTER attacks to avoid VM overload

set -e

WAZUH="wazuh"
DASHBOARD_URL="https://192.168.122.247"
OS_URL="https://192.168.122.247:9200"

echo "============================================"
echo "  CE 4309 Final Project - Demo"
echo "============================================"

# Step 1: Verify VMs
echo ""
echo "[1] Checking VMs..."
ssh -o ConnectTimeout 5 $WAZUH "echo ok" >/dev/null 2>&1 && echo "  Wazuh VM: OK" || echo "  Wazuh VM: DOWN"
curl -s http://192.168.122.10:5000/ >/dev/null 2>&1 && echo "  Defense VM: OK" || echo "  Defense VM: DOWN"

# Step 2: Clean state
echo ""
echo "[2] Cleaning state..."
ssh $WAZUH "sudo iptables -F INPUT" 2>/dev/null
ssh $WAZuh "sudo /var/ossec/bin/agent_control -l" 2>/dev/null | grep "002" && echo "  Agent 002: Active" || echo "  Agent 002: Check needed"

# Step 3: Ensure dashboard is OFF during attacks
echo ""
echo "[3] Ensuring dashboard is off during attacks..."
DASH_STATUS=$(ssh $WAZUH "sudo systemctl is-active wazuh-dashboard" 2>/dev/null)
if [ "$DASH_STATUS" = "active" ]; then
    echo "  Stopping dashboard..."
    ssh $WAZUH "sudo systemctl stop wazuh-dashboard" 2>/dev/null
fi
echo "  Dashboard: OFF"

# Step 4: Send attacks
echo ""
echo "[4] Sending brute force attack (5 failed logins)..."
for i in 1 2 3 4 5; do
    curl -s -X POST "http://192.168.122.10:5000/" -d "username=attacker&password=wrong$i" > /dev/null
    sleep 2
done
echo "  Sent 5 failed login attempts"

# Step 5: Wait for detection
echo ""
echo "[5] Waiting for detection (10s)..."
sleep 10

# Step 6: Show results
echo ""
echo "[6] Results..."
echo ""
echo "--- Detected Alerts ---"
ALERT_COUNT=$(curl -sk -u admin:admin "$OS_URL/wazuh-alerts-*/_count?q=rule.id:100101" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null)
echo "  OpenSearch: $ALERT_COUNT alerts indexed"

echo ""
echo "--- Alert Details (srcip, user, status) ---"
curl -sk -u admin:admin -X POST "$OS_URL/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"rule.id":"100101"}},"size":5,"sort":[{"timestamp":{"order":"desc"}}]}' 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
for h in d.get('hits',{}).get('hits',[]):
    s = h.get('_source',{})
    data = s.get('data',{})
    print(f'  {s.get(\"timestamp\",\"?\")[:19]} | srcip={data.get(\"srcip\",\"?\")} | user={data.get(\"dstuser\",\"?\")} | status={data.get(\"cppbank_status\",\"?\")}')
" 2>/dev/null || echo "  (query failed)"

echo ""
echo "--- Active Response ---"
ssh $WAZUH "sudo tail -3 /var/ossec/logs/active-responses.log" 2>/dev/null || echo "  (log unavailable)"

echo ""
echo "--- Blocked IPs ---"
ssh $WAZUH "sudo iptables -L INPUT -n | grep DROP" 2>/dev/null || echo "  (no blocks or iptables unavailable)"

# Step 7: Start dashboard for visual demo
echo ""
echo "[7] Starting dashboard for visual demo..."
ssh $WAZUH "sudo systemctl start wazuh-dashboard" 2>/dev/null
echo "  Dashboard: ON"
echo "  Open: $DASHBOARD_URL (admin/admin)"

echo ""
echo "============================================"
echo "  Demo complete!"
echo "  Dashboard: $DASHBOARD_URL"
echo "  OpenSearch: $OS_URL"
echo "============================================"
