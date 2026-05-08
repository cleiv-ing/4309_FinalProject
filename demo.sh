#!/usr/bin/env bash
# CE 4309 Final Project - Complete Demo Script
set -u

VM="192.168.122.247"
TARGET="192.168.122.10"
DEMO_USER="live_demo_$(date +%H%M%S)"
AI_LOG="/tmp/ai-agent-demo.log"

echo "=========================================="
echo "CE 4309 Wazuh IDS Demo - Starting"
echo "=========================================="

echo "[Step 1] Verify Wazuh Manager"
ssh "wazuhadmin@$VM" "sudo /var/ossec/bin/wazuh-control status | head -15"

echo ""
echo "[Step 1b] Configure Stable Demo Services"
ssh "wazuhadmin@$VM" "sudo systemctl stop wazuh-auto-response 2>/dev/null || true; sudo systemctl start wazuh-dashboard; sudo systemctl start wazuh-forwarder; systemctl is-active wazuh-dashboard wazuh-forwarder"

echo ""
echo "[Step 2] Dashboard & OpenSearch"
curl -sk -u admin:admin "https://$VM:9200/_cluster/health" | python3 -c "import sys,json; print('OpenSearch:', json.load(sys.stdin).get('status'))"
ssh "wazuhadmin@$VM" "sudo systemctl is-active wazuh-dashboard"

echo ""
echo "[Step 3] Alert Count"
curl -sk -u admin:admin "https://$VM:9200/wazuh-alerts-*/_count?q=rule.id:100101" | python3 -c "import sys,json; print('Total alerts:', json.load(sys.stdin).get('count'))"

echo ""
echo "[Step 3b] Generate Fresh Attacks"
rm -f "$AI_LOG"
echo "Sending 3 fresh failed logins as user: $DEMO_USER"
for i in 1 2 3; do
  curl -s -o /dev/null -X POST "http://$TARGET:5000/" -d "username=$DEMO_USER&password=wrong$i"
done
sleep 10

echo ""
echo "[Step 4] Latest Alert"
ssh "wazuhadmin@$VM" "sudo tail -1 /var/ossec/logs/alerts/alerts.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print('srcip:', d.get('data',{}).get('srcip')); print('user:', d.get('data',{}).get('dstuser')); print('status:', d.get('data',{}).get('cppbank_status'))"

echo ""
echo "[Step 4b] Verify Fresh Alerts Are Indexed in OpenSearch"
curl -sk -u admin:admin "https://$VM:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d "{\"query\":{\"query_string\":{\"query\":\"$DEMO_USER\"}},\"size\":5,\"sort\":[{\"timestamp\":{\"order\":\"desc\"}}]}" | python3 -c "import sys,json; d=json.load(sys.stdin); hits=d.get('hits',{}).get('hits',[]); print('Fresh indexed alerts:', len(hits)); [print('  '+h.get('_source',{}).get('timestamp','?')+' srcip='+h.get('_source',{}).get('data',{}).get('srcip','?')+' user='+h.get('_source',{}).get('data',{}).get('dstuser','?')) for h in hits[:3]]"

echo ""
echo "[Step 4c] AI Agent Decision Log"
cd /var/lib/hermes-agent-official/workspace || exit 1
timeout 14 python3 -u ai-soc-agent.py > "$AI_LOG" 2>&1 || true
cat "$AI_LOG"

echo ""
echo "[Step 4d] Verify AI Decision Is Visible in OpenSearch/Dashboard"
curl -sk -u admin:admin "https://$VM:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d "{\"query\":{\"term\":{\"rule.id\":\"100201\"}},\"size\":3,\"sort\":[{\"timestamp\":{\"order\":\"desc\"}}]}" | python3 -c "import sys,json; d=json.load(sys.stdin); hits=d.get('hits',{}).get('hits',[]); print('AI decision alerts:', len(hits)); [print('  '+h.get('_source',{}).get('timestamp','?')+' action='+h.get('_source',{}).get('data',{}).get('ai_action','?')+' srcip='+h.get('_source',{}).get('data',{}).get('srcip','?')) for h in hits]"

echo ""
echo "[Step 5] Manual Active Response Test"
TEST_BLOCK_IP="192.168.122.250"
ssh "wazuhadmin@$VM" "sudo iptables -D INPUT -s $TEST_BLOCK_IP -j DROP 2>/dev/null || true; echo '$TEST_BLOCK_IP add' | sudo /var/ossec/active-response/bin/custom-firewall-drop; sudo iptables -C INPUT -s $TEST_BLOCK_IP -j DROP && echo 'Verified block for $TEST_BLOCK_IP'"
ssh "wazuhadmin@$VM" "sudo iptables -L INPUT -n --line-numbers | grep DROP"

echo ""
echo "[Step 6] AI SOC Agent Demo"
echo "AI agent was already exercised in Step 3b/4c."
echo "Note: 192.168.122.1 is protected because it is the admin/demo host."
echo "A separate attacker laptop/IP will be automatically blocked by the AI agent."
echo "For separate attackers, AI blocks both Wazuh manager iptables and Windows Defender firewall TCP/5000."
echo "AI decisions are indexed as rule.id=100201 for dashboard visibility."

echo ""
echo "=========================================="
echo "Demo Complete"
echo "=========================================="
