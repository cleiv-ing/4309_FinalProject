# Wazuh Active Response Defense System - Setup Guide

## Quick Start (For Demo)

### 1. Start the VMs
```bash
# Start Wazuh Manager VM
virsh start ce4309-wazuh

# Start Defense VM  
virsh start ce4309-defense-win
```

### 2. Verify Services Running
```bash
# SSH to Wazuh Manager
ssh wazuhadmin@192.168.122.247

# Check services
sudo /var/ossec/bin/wazuh-control status

# Should show: wazuh-analysisd, wazuh-execd, wazuh-remoted all running
```

### 3. Run the Demo Attack
```bash
# From your laptop (not inside VMs):
for i in 1 2 3 4 5; do
  curl -s -X POST "http://192.168.122.10:5000/" \
    -d "username=bankuser&password=wrong$i"
done
```

### 4. Verify Detection
```bash
# Check alerts generated
ssh wazuhadmin@192.168.122.247 "sudo grep 'Rule: 100101' /var/ossec/logs/alerts/alerts.log | tail -3"

# Check OpenSearch index
ssh wazuhadmin@192.168.122.247 "curl -sk -u admin:admin 'https://localhost:9200/wazuh-alerts-4.x-2026.05.05/_count?q=rule.id:100101'"
```

### 5. Verify Active Response (Manual Trigger)
```bash
# Test blocking an IP
ssh wazuhadmin@192.168.122.247 "echo '192.168.122.99 add' | sudo /var/ossec/active-response/bin/custom-firewall-drop"

# Verify blocked in iptables
ssh wazuhadmin@192.168.122.247 "sudo iptables -L INPUT -n | grep DROP"

# Unblock (after test)
ssh wazuhadmin@192.168.122.247 "sudo iptables -D INPUT -s 192.168.122.99 -j DROP"
```

---

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Attack Target  │────▶│  Defense VM    │────▶│  Wazuh Manager │
│  (Flask App)   │     │  (Windows)    │     │  (Linux)      │
│ 192.168.122.10│     │ 192.168.122.10│     │192.168.122.247│
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                      │
                                                      ▼
                                               ┌─────────────────┐
                                               │  OpenSearch      │
                                               │  Dashboard       │
                                               │ localhost:9200  │
                                               └─────────────────┘
```

---

## Component Setup (If Rebuilding)

### Wazuh Manager VM Setup

1. **Install Wazuh Manager**
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && \
sudo bash wazuh-install.sh -a
```

2. **Add Decoder** (`/var/ossec/etc/decoders/0025-cpp-bank.xml`)
```xml
<decoder name="cpp-bank-ip">
  <prematch>defense-vm IP=</prematch>
  <regex>IP=(\S+) | USER=(\S+) | STATUS=(\S+)</regex>
  <order>srcip</order>
</decoder>
```

3. **Add Custom Active Response Script** (`/var/ossec/active-response/bin/custom-firewall-drop`)
```bash
#!/bin/bash
LOG_FILE="/var/ossec/logs/active-responses.log"
IPTABLES="/usr/sbin/iptables"

while read -r line; do
    SRCIP=$(echo "$line" | awk '{print $1}')
    [ -z "$SRCIP" ] && continue
    $IPTABLES -A INPUT -s "$SRCIP" -j DROP 2>/dev/null
    [ $? -eq 0 ] && echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: SUCCESS - Blocked $SRCIP" >> "$LOG_FILE"
done
exit 0
```
```bash
sudo chmod +x /var/ossec/active-response/bin/custom-firewall-drop
```

4. **Configure Active Response** (`/var/ossec/etc/shared/ar.conf`)
```
100101 - custom-firewall-drop - 300
```

5. **Install Python Forwarder** (replaces broken Filebeat)
```bash
# Copy /usr/local/bin/wazuh-forwarder.py from working VM
# Or use the forwarder script

# Create systemd service
sudo tee /etc/systemd/system/wazuh-forwarder.service > /dev/null << 'EOF'
[Unit]
Description=Wazuh Alert Forwarder
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wazuh-forwarder.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wazuh-forwarder
sudo systemctl start wazuh-forwarder
```

### Defense VM (Windows) Setup

1. **Install Wazuh Agent**
```powershell
# Download from https://www.wazuh.com/downloads/
# Install ossec-agent
```

2. **Configure Agent** (`C:\Program Files (x86)\ossec-agent\ossec.conf`)
```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.122.247</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\logs\auth.log</location>
  </localfile>
</ossec_config>
```

3. **Start Agent**
```powershell
Start-Service -Name WazuhSvc
```

### Flask App Setup (On Defense VM)

1. **Install Python Dependencies**
```bash
pip install flask
```

2. **Run Flask App**
```bash
cd /path/to/4309_FinalProject
python Troy_Login_Attack_Simulation/app.py
```

---

## Verification Commands

| Check | Command |
|-------|---------|
| Wazuh services | `ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/wazuh-control status"` |
| Agent connected | `ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/agent_control -l"` |
| Alerts generated | `ssh wazuhadmin@192.168.122.247 "sudo grep 'Rule: 100101' /var/ossec/logs/alerts/alerts.log | wc -l"` |
| OpenSearch alerts | `ssh wazuhadmin@192.168.122.247 "curl -sk -u admin:admin 'https://localhost:9200/wazuh-alerts-4.x-*/_count'"` |
| Active response log | `ssh wazuhadmin@192.168.122.247 "sudo tail /var/ossec/logs/active-responses.log"` |
| Blocked IPs | `ssh wazuhadmin@192.168.122.247 "sudo iptables -L INPUT -n | grep DROP"` |

---

## Troubleshooting

### Filebeat Won't Start
```
# Error: pthread_create failed: Operation not permitted
# Fix: Use Python forwarder instead (already configured above)
```

### No Alerts in OpenSearch
```bash
# Check forwarder is running
ssh wazuhadmin@192.168.122.247 "ps aux | grep wazuh-forwarder"

# Restart if needed
ssh wazuhadmin@192.168.122.247 "sudo systemctl restart wazuh-forwarder"
```

### Agent Not Connecting
```bash
# Check agent status on Windows
Get-Service -Name WazuhSvc

# Restart if needed
Restart-Service -Name WazuhSvc
```

---

## Current Status

- **Detection:** ✅ Working (Rule 100101 triggers on failed logins)
- **Indexing:** ✅ Working (Alerts indexed to OpenSearch)
- **Active Response:** ⚠️ Manual trigger works, auto-trigger needs additional config

---

## IP Addresses

| VM | IP |
|---|---|
| Defense VM (Windows) | 192.168.122.10 |
| Wazuh Manager | 192.168.122.247 |
| Your Laptop (attacker) | 192.168.122.1 |