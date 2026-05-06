# CE 4309 Final Project: Wazuh Bank Login Detection with Active Response

A complete Wazuh-based intrusion detection and active response system that monitors a Flask bank login application for failed login attempts.

## Architecture

```
[Attacker] ---POST /login---> [Defense VM: Flask App]
                                  |
                            Writes auth.log
                                  |
                              [Wazuh Agent]
                                  |
                           TCP 1514 (events)
                                  |
                            [Wazuh Manager]
                                  |
                    +-------------+-------------+
                    |             |             |
               [Decoder]     [Rules]     [Active Response]
               cpp-bank     100101      custom-firewall-drop
                    |             |             |
                    +-------------+-------------+
                                  |
                           [OpenSearch Index]
                                  |
                          [Wazuh Dashboard]
                          https://192.168.122.247
```

## Network Map

| Host | IP | Role |
|------|-----|------|
| NixOS Host (attacker) | 192.168.122.1 | Runs curl attack commands |
| Defense VM (Windows 11) | 192.168.122.10 | Flask app + Wazuh Agent |
| Wazuh Manager (Ubuntu) | 192.168.122.247 | All-in-one manager + AR |

## Quick Start (Demo)

### 1. Start VMs
```
virsh start ce4309-wazuh
virsh start ce4309-defense-win
```

### 2. Verify Services
```bash
# Wazuh Manager status
ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/wazuh-control status"
# Expected: all services running

# Agent connected
ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/agent_control -l"
# Expected: Agent 002 (ce4309-defense-win) Active

# Flask app running
curl -s http://192.168.122.10:5000/
# Expected: HTML login page returned
```

### 3. Run Attack (from NixOS host)
```bash
for i in 1 2 3 4 5; do
  curl -s -X POST "http://192.168.122.10:5000/" \
    -d "username=bankuser&password=wrong$i"
done
```

### 4. Verify Detection
```bash
# Check alerts in JSON log
ssh wazuhadmin@192.168.122.247 "sudo grep '100101' /var/ossec/logs/alerts/alerts.json | tail -3"

# Check OpenSearch count
ssh wazuhadmin@192.168.122.247 "curl -sk -u admin:admin 'https://localhost:9200/wazuh-alerts-*/_count?q=rule.id:100101'"

# View in Dashboard
# Open https://192.168.122.247 in browser (admin/admin)
```

### 5. Verify Active Response (Manual)
```bash
# Block a test IP
ssh wazuhadmin@192.168.122.247 "echo '192.168.122.99 add' | sudo /var/ossec/active-response/bin/custom-firewall-drop"

# Confirm block
ssh wazuhadmin@192.168.122.247 "sudo iptables -L INPUT -n | grep 192.168.122.99"
# Expected: DROP all -- 192.168.122.99

# Unblock
ssh wazuhadmin@192.168.122.247 "sudo iptables -D INPUT -s 192.168.122.99 -j DROP"
```

## Project Structure

```
4309_FinalProject/
├── Troy_Login_Attack_Simulation/    # Flask app (on Defense VM)
│   ├── app.py                       # Bank login application
│   ├── templates/login.html         # Login page template
│   └── auth.log                     # Generated auth log (created at runtime)
├── wazuh/
│   ├── decoders/
│   │   ├── 0025-cpp-bank.xml        # Custom decoder for auth.log format
│   │   └── local_decoder.xml        # Existing local decoder
│   ├── rules/
│   │   └── local_rules.xml          # Rules 100100-100102
│   ├── shared/
│   │   └── ar.conf                  # Active response configuration
│   ├── ossec-manager-snippet.xml    # Manager config additions
│   └── ossec-agent-snippet.xml      # Agent config additions
├── docs/                            # Project documentation
└── tools/                           # Utility scripts
```

## Component Details

### Flask App (Defense VM)
- **Location**: `C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\app.py`
- **Credentials**: username=`bankuser`, password=`SecurePass123`
- **Log format**: `YYYY-MM-DD HH:MM:SS hostname IP=<ip> | USER=<user> | STATUS=<status> | REASON=<reason>`
- **Log location**: `...\Troy_Login_Attack_Simulation\auth.log`

### Wazuh Decoder (`wazuh/decoders/0025-cpp-bank.xml`)
Matches pipe-delimited auth.log format and extracts:
- `srcip` - Source IP address
- `user` - Username attempted
- `cppbank_status` - FAILED or SUCCESS

### Wazuh Rules (`wazuh/rules/local_rules.xml`)
| Rule | Level | Description |
|------|-------|-------------|
| 100100 | 0 | CPP Bank login (parent rule) |
| 100101 | 7 | CPP Bank login failed (triggers on STATUS=FAILED) |
| 100102 | 3 | CPP Bank login successful (triggers on STATUS=SUCCESS) |

### Active Response (`wazuh/shared/ar.conf`)
- Rule 100101 triggers `custom-firewall-drop` script
- Blocks attacker IP via iptables for 300 seconds
- Script location: `/var/ossec/active-response/bin/custom-firewall-drop`

### OpenSearch Forwarder
- Python-based forwarder (`/usr/local/bin/wazuh-forwarder.py`)
- Tails `alerts.json` and indexes to OpenSearch
- Systemd service: `wazuh-forwarder`

## Full Rebuild Instructions

### Wazuh Manager VM (Ubuntu)

1. **Install Wazuh all-in-one**:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

2. **Install custom decoder**:
```bash
sudo cp wazuh/decoders/0025-cpp-bank.xml /var/ossec/etc/decoders/
sudo chown root:wazuh /var/ossec/etc/decoders/0025-cpp-bank.xml
```

3. **Install custom rules**:
```bash
sudo cp wazuh/rules/local_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
```

4. **Install active response script**:
```bash
sudo tee /var/ossec/active-response/bin/custom-firewall-drop > /dev/null << 'SCRIPT'
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
SCRIPT
sudo chmod +x /var/ossec/active-response/bin/custom-firewall-drop
sudo chown root:wazuh /var/ossec/active-response/bin/custom-firewall-drop
```

5. **Configure active response**:
```bash
sudo cp wazuh/shared/ar.conf /var/ossec/etc/shared/ar.conf
sudo chown root:wazuh /var/ossec/etc/shared/ar.conf
```

6. **Install Python forwarder**:
```bash
sudo cp tools/wazuh-forwarder.py /usr/local/bin/
sudo chmod +x /usr/local/bin/wazuh-forwarder.py

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

7. **Restart Wazuh**:
```bash
sudo /var/ossec/bin/wazuh-control restart
```

### Defense VM (Windows 11)

1. **Install Python 3** and Flask:
```powershell
pip install flask
```

2. **Create the Flask app** at `C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\app.py`

3. **Install Wazuh Agent**:
   - Download from https://www.wazuh.com/downloads/
   - Set manager address to `192.168.122.247`

4. **Configure agent** (`C:\Program Files (x86)\ossec-agent\ossec.conf`):
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
    <location>C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\auth.log</location>
  </localfile>
</ossec_config>
```

5. **Start the agent**:
```powershell
Start-Service -Name WazuhSvc
```

6. **Start the Flask app**:
```powershell
cd C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation
python app.py
```

## Credentials

| Service | Username | Password |
|---------|----------|----------|
| Flask App | bankuser | SecurePass123 |
| Wazuh Dashboard | admin | admin |
| OpenSearch | admin | admin |
| Wazuh API | wazuh | wazuh |
| Wazuh Manager SSH | wazuhadmin | 1747 |
| Defense VM SSH | defense | 7471 |

## Verification Checklist

- [ ] `virsh list --all` shows both VMs running
- [ ] `ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/wazuh-control status"` - all running
- [ ] `ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/agent_control -l"` - Agent 002 Active
- [ ] `curl http://192.168.122.10:5000/` - returns login page
- [ ] Send 5 failed logins via curl
- [ ] `ssh wazuh "sudo grep '100101' /var/ossec/logs/alerts/alerts.json | tail -1"` - shows alert with srcip
- [ ] `curl -sk -u admin:admin 'https://localhost:9200/wazuh-alerts-*/_count?q=rule.id:100101'` - count > 0
- [ ] Manual AR test blocks IP in iptables
- [ ] https://192.168.122.247 dashboard shows alerts

## Troubleshooting

### No alerts after attack
```bash
# Check agent is forwarding
ssh wazuhadmin@192.168.122.247 "sudo tail /var/ossec/logs/archives/archives.log | grep 002"

# Check decoder is matching
ssh wazuhadmin@192.168.122.247 "sudo /var/ossec/bin/wazuh-logtest" then paste a log line

# Restart agent on Windows
ssh defense@192.168.122.10 "powershell -Command Restart-Service WazuhSvc"
```

### No alerts in OpenSearch
```bash
# Check forwarder is running
ssh wazuhadmin@192.168.122.247 "sudo systemctl status wazuh-forwarder"

# Reset forwarder offset
ssh wazuhadmin@192.168.122.247 "echo 0 | sudo tee /var/lib/wazuh-forwarder/offset.txt"
ssh wazuhadmin@192.168.122.247 "sudo systemctl restart wazuh-forwarder"
```

### Agent not connecting
```powershell
# On Defense VM, check agent log
Get-Content "C:\Program Files (x86)\ossec-agent\logs\ossec.log" -Tail 20

# Re-enroll if needed
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 192.168.122.247
Restart-Service WazuhSvc
```

### Flask app not writing logs
```powershell
# Check file exists
Test-Path "C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\auth.log"

# Check app is listening
netstat -ano | findstr 5000
```

## Known Limitations

- **Auto-trigger Active Response**: Wazuh has a known limitation where auto-triggering active response on agent-generated alerts may not work reliably. The manual trigger (`echo '<IP> add' | custom-firewall-drop`) always works and can be demonstrated as proof of concept.
- **Filebeat**: The bundled Filebeat has a `pthread_create` permission error in this environment. The Python forwarder replaces it.

## Team

- Giovanni (giovanni-wazuh-active-response branch)
- CE 4309 Cybersecurity Course
