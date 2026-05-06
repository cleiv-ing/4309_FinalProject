#!/bin/bash
# CE 4309 Final Project - Demo Script
# Run this on the NixOS host

echo "============================================"
echo "  CE 4309 Final Project - Demo Script"
echo "============================================"

# Step 1: Verify VMs are running
echo ""
echo "Step 1: Checking VMs..."
ping -c 1 -W 2 192.168.122.10 > /dev/null 2>&1 && echo "  Defense VM: OK" || echo "  Defense VM: DOWN"
ping -c 1 -W 2 192.168.122.247 > /dev/null 2>&1 && echo "  Wazuh VM: OK" || echo "  Wazuh VM: DOWN"

# Step 2: Verify services
echo ""
echo "Step 2: Checking services..."
ssh -o ConnectTimeout 5 wazuh "sudo systemctl is-active wazuh-analysisd wazuh-execd wazuh-remoted wazuh-db" 2>/dev/null
ssh -o ConnectTimeout 5 wazuh "sudo /var/ossec/bin/agent_control -l" 2>/dev/null

# Step 3: Start AI SOC Agent
echo ""
echo "Step 3: Starting AI SOC Agent..."
cd /var/lib/hermes-agent-official/workspace
python3 -u ai-soc-agent.py > /tmp/ai-agent.log 2>&1 &
AGENT_PID=$!
echo "  Agent started (PID: $AGENT_PID)"
sleep 5
cat /tmp/ai-agent.log

# Step 4: Send attacks
echo ""
echo "Step 4: Sending attack (5 failed logins)..."
for i in 1 2 3 4 5; do
  curl -s -X POST "http://192.168.122.10:5000/" -d "username=demo&password=wrong$i" > /dev/null
done
echo "  Sent"

# Step 5: Wait and show results
echo ""
echo "Step 5: Waiting for detection (15s)..."
sleep 15

echo ""
echo "=== AI SOC Agent Output ==="
cat /tmp/ai-agent.log

echo ""
echo "=== Active Response Log ==="
ssh -o ConnectTimeout 5 wazuh "sudo tail -5 /var/ossec/logs/active-responses.log" 2>/dev/null

echo ""
echo "=== Blocked IPs ==="
ssh -o ConnectTimeout 5 wazuh "sudo iptables -L INPUT -n | grep DROP" 2>/dev/null

echo ""
echo "=== OpenSearch Alert Count ==="
curl -sk -u admin:admin "https://192.168.122.247:9200/wazuh-alerts-*/_count?q=rule.id:100101" 2>/dev/null

echo ""
echo "============================================"
echo "  Dashboard: https://192.168.122.247"
echo "  Credentials: admin / admin"
echo "============================================"

# Cleanup
echo ""
read -p "Press Enter to cleanup (unblock IPs and stop agent)..."
kill $AGENT_PID 2>/dev/null
ssh -o ConnectTimeout 5 wazuh "sudo iptables -F INPUT" 2>/dev/null
echo "Cleanup done."
