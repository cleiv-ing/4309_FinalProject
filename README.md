# CE 4309 Final Project - Demo Setup Guide

## What This Guide Covers
- How to set up the complete Wazuh-based bank login detection system from scratch
- All commands needed on each VM
- Architecture overview
- Credentials
- Verification checklist

---

## Network Map

| Host | IP | Role |
|------|-----|------|
| Attacker (any machine) | any | Sends failed login requests |
| Defense VM (Windows 11) | 192.168.122.10 | Flask bank app + Wazuh Agent |
| Wazuh Manager (Ubuntu) | 192.168.122.247 | All-in-one SIEM + Active Response |

---

## Architecture

```
[Attacker] --POST /login--> [Defense VM: Flask App :5000]
                                  |
                            Writes auth.log
                                  |
                            [Wazuh Agent]
                                  |
                           TCP 1514 (events)
                                  |
                            [Wazuh Manager :192.168.122.247]
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
                    [Wazuh Dashboard :443]
                    https://192.168.122.247
```

---

## Part 1: Wazuh Manager VM Setup (Ubuntu)

### 1.1 Install Wazuh All-in-One

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

After install, Wazuh is at `/var/ossec/` and OpenSearch runs on port 9200.

### 1.2 Deploy Custom Decoder

```bash
sudo tee /var/ossec/etc/decoders/0025-cpp-bank.xml > /dev/null << 'EOF'
<decoder name="cpp-bank">
  <prematch>IP=</prematch>
  <regex>IP=(\S+) \| USER=(\S+) \| STATUS=(\S+)</regex>
  <order>srcip,user,cppbank_status</order>
</decoder>
EOF
sudo chown root:wazuh /var/ossec/etc/decoders/0025-cpp-bank.xml
```

### 1.3 Deploy Custom Rules

```bash
sudo tee /var/ossec/etc/rules/local_rules.xml > /dev/null << 'EOF'
<!-- CPP Bank local rules -->
<group name="cpp-bank">
  <rule id="100100" level="0">
    <match>STATUS=</match>
    <description>CPP Bank login</description>
  </rule>
  <rule id="100101" level="7">
    <if_sid>100100</if_sid>
    <match>STATUS=FAILED</match>
    <description>CPP Bank login failed</description>
  </rule>
  <rule id="100102" level="3">
    <if_sid>100100</if_sid>
    <match>STATUS=SUCCESS</match>
    <description>CPP Bank login successful</description>
  </rule>
</group>
EOF
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
```

### 1.4 Deploy Active Response Script

```bash
sudo tee /var/ossec/active-response/bin/custom-firewall-drop > /dev/null << 'SCRIPT'
#!/bin/bash
LOG_FILE="/var/ossec/logs/active-responses.log"
IPTABLES="/usr/sbin/iptables"

INPUT=$(cat)

# Extract srcip - support both plain text and JSON
SRCIP=""
if echo "$INPUT" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
    SRCIP=$(echo "$INPUT" | awk '{print $1}')
else
    SRCIP=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    srcip = d.get('parameters', {}).get('alert', {}).get('data', {}).get('srcip', '')
    if not srcip:
        srcip = d.get('srcip', '')
    print(srcip)
except:
    print('')
" 2>/dev/null)
fi

[ -z "$SRCIP" ] && echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: ERROR - No srcip" >> "$LOG_FILE" && exit 1
! echo "$SRCIP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' && echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: ERROR - Invalid IP: $SRCIP" >> "$LOG_FILE" && exit 1

if $IPTABLES -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: SKIP - $SRCIP already blocked" >> "$LOG_FILE"
    exit 0
fi

$IPTABLES -A INPUT -s "$SRCIP" -j DROP 2>/dev/null
[ $? -eq 0 ] && echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: SUCCESS - Blocked $SRCIP" >> "$LOG_FILE" || echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: FAILED - Could not block $SRCIP" >> "$LOG_FILE"
exit 0
SCRIPT
sudo chmod +x /var/ossec/active-response/bin/custom-firewall-drop
sudo chown root:wazuh /var/ossec/active-response/bin/custom-firewall-drop
```

### 1.5 Configure Active Response in ossec.conf

Add to `/var/ossec/etc/ossec.conf` (before the `<localfile>` section near the end):

```xml
  <command>
    <name>custom-firewall-drop</name>
    <executable>custom-firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>custom-firewall-drop</command>
    <location>server</location>
    <rules_id>100101</rules_id>
    <timeout>300</timeout>
  </active-response>
```

### 1.6 Configure Agent-Side AR (ar.conf)

```bash
printf 'restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\nrestart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\nrestart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\nblock-ip300 - block-ip.bat - 300\n' | sudo tee /var/ossec/etc/shared/ar.conf > /dev/null
```

### 1.7 Install OpenSearch Forwarder

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

### 1.8 Install Auto-Response Watcher

```bash
sudo cp tools/wazuh-auto-response.py /usr/local/bin/
sudo chmod +x /usr/local/bin/wazuh-auto-response.py

sudo cp tools/wazuh-auto-response.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wazuh-auto-response
sudo systemctl start wazuh-auto-response
```

### 1.9 Disable UFW

```bash
sudo ufw disable
```

### 1.10 Restart Wazuh

```bash
sudo /var/ossec/bin/wazuh-control restart
```

---

## Part 2: Defense VM Setup (Windows 11)

### 2.1 Install Python and Flask

```powershell
pip install flask
```

### 2.2 Create Flask App

Create folder `C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\`

Create `app.py`:

```python
from datetime import datetime
import os
from pathlib import Path
from flask import Flask, render_template, request

APP_DIR = Path(__file__).resolve().parent
LOG_FILE = Path(r'C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\auth.log')

VALID_USERNAME = os.environ.get('CPPBANK_USERNAME', 'bankuser')
VALID_PASSWORD = os.environ.get('CPPBANK_PASSWORD', 'SecurePass123')

app = Flask(__name__)

def clean_log_value(value):
    return str(value).replace('|', '/').replace('\r', ' ').replace('\n', ' ').strip()

def get_client_ip():
    if os.environ.get('CPPBANK_TRUST_PROXY') == '1':
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        if forwarded_for:
            return clean_log_value(forwarded_for.split(',')[0])
    return clean_log_value(request.remote_addr or 'unknown')

def write_log(username, ip, status, reason):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = (
        f'{timestamp} defense-vm IP={clean_log_value(ip)} | USER={clean_log_value(username)} | '
        f'STATUS={clean_log_value(status)} | REASON={clean_log_value(reason)}\n'
    )
    with LOG_FILE.open('a', encoding='utf-8') as file:
        file.write(log_entry)

@app.get('/healthz')
def healthz():
    return {'status': 'ok'}

@app.route('/', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip = get_client_ip()
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            write_log(username, ip, 'SUCCESS', 'Valid login')
            message = 'Login successful. Welcome to CPP Bank.'
        else:
            write_log(username, ip, 'FAILED', 'Invalid username or password')
            message = 'Login failed. Invalid username or password.'
    return render_template('login.html', message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

Create `templates\login.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CPP Bank Login</title>
    <style>
        body { align-items: center; background: #eef2f3; display: flex; justify-content: center; min-height: 100vh; margin: 0; font-family: Arial, sans-serif; }
        .login-box { background: white; border-radius: 10px; box-shadow: 0 0 10px gray; max-width: 350px; padding: 25px; text-align: center; width: calc(100% - 32px); }
        input { box-sizing: border-box; margin: 10px 0; padding: 10px; width: 100%; }
        button { background-color: #004080; border: none; color: white; cursor: pointer; padding: 10px 20px; }
        .message { font-weight: bold; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>CPP Bank Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
        <div class="message">{{ message }}</div>
    </div>
</body>
</html>
```

### 2.3 Install and Configure Wazuh Agent

Download from https://www.wazuh.com/downloads/ and install.

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.122.247</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>windows, windows10</config-profile>
    <crypto_method>aes</crypto_method>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
  <active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
  <localfile>
    <log_format>syslog</log_format>
    <location>C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\auth.log</location>
  </localfile>
</ossec_config>
```

### 2.4 Start Services

```powershell
# Start Flask
cd C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation
python app.py

# Start Wazuh Agent
Start-Service WazuhSvc
```

---

## Part 3: Credentials

| Service | Username | Password |
|---------|----------|----------|
| Flask App | bankuser | SecurePass123 |
| Wazuh Dashboard | admin | admin |
| OpenSearch | admin | admin |
| Wazuh API | wazuh | wazuh |
| Manager SSH | wazuhadmin | 1747 |
| Defense VM SSH | defense | 7471 |

---

## Part 4: Verification Checklist

```bash
# 1. Manager services
ssh wazuh "sudo /var/ossec/bin/wazuh-control status"

# 2. Agent connected
ssh wazuh "sudo /var/ossec/bin/agent_control -l"

# 3. Flask responding
curl -s http://192.168.122.10:5000/

# 4. Send attack
for i in 1 2 3 4 5; do curl -s -X POST "http://192.168.122.10:5000/" -d "username=test&password=wrong$i"; done

# 5. Check alerts (wait 10s)
ssh wazuh "sudo grep '100101' /var/ossec/logs/alerts/alerts.json | tail -1"

# 6. Check OpenSearch
ssh wazuh "curl -sk -u admin:admin 'https://localhost:9200/wazuh-alerts-*/_count?q=rule.id:100101'"

# 7. Check AR triggered
ssh wazuh "sudo tail -3 /var/ossec/logs/active-responses.log"

# 8. Check iptables
ssh wazuh "sudo iptables -L INPUT -n | grep DROP"

# 9. Open Dashboard
# https://192.168.122.247 (admin/admin)
```

---

## Part 5: Demo Script

### Terminal 1 - Watch AR triggers:
```bash
ssh wazuh "sudo tail -f /var/ossec/logs/active-responses.log"
```

### Terminal 2 - Send attack:
```bash
for i in 1 2 3 4 5; do curl -s -X POST "http://192.168.122.10:5000/" -d "username=attacker&password=wrong$i"; done
```

### What happens:
1. Flask returns "Login failed" messages
2. AR log shows `SUCCESS - Blocked <IP>` within ~5-10 seconds
3. iptables shows DROP rule: `ssh wazuh "sudo iptables -L INPUT -n | grep DROP"`
4. Wazuh Dashboard (https://192.168.122.247) shows alerts with srcip data

### Cleanup:
```bash
ssh wazuh "sudo iptables -D INPUT -s <ATTACKER_IP> -j DROP"
```

---

## Troubleshooting

### Agent not connecting
```powershell
# On Defense VM:
Restart-Service WazuhSvc
```

### No alerts
```bash
# Check auth.log has entries
ssh defense@192.168.122.10 "type 'C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\auth.log'" | tail -3

# Test decoder manually
ssh wazuh "echo '2026-05-06 12:00:00 defense-vm IP=10.0.0.1 | USER=test | STATUS=FAILED | REASON=bad' | sudo /var/ossec/bin/wazuh-logtest"
```

### No AR trigger
```bash
# Check watcher
ssh wazuh "sudo systemctl status wazuh-auto-response"

# Manual AR test
ssh wazuh "echo '10.0.0.99 add' | sudo /var/ossec/active-response/bin/custom-firewall-drop"
ssh wazuh "sudo iptables -L INPUT -n | grep 10.0.0.99"
ssh wazuh "sudo iptables -D INPUT -s 10.0.0.99 -j DROP"
```

### OpenSearch not indexing
```bash
ssh wazuh "sudo systemctl status wazuh-forwarder"
```

---

## File Locations

### Wazuh Manager (192.168.122.247)
| File | Path |
|------|------|
| Decoder | `/var/ossec/etc/decoders/0025-cpp-bank.xml` |
| Rules | `/var/ossec/etc/rules/local_rules.xml` |
| AR Script | `/var/ossec/active-response/bin/custom-firewall-drop` |
| AR Config | `/var/ossec/etc/shared/ar.conf` |
| ossec.conf AR | `/var/ossec/etc/ossec.conf` |
| Forwarder | `/usr/local/bin/wazuh-forwarder.py` |
| Watcher | `/usr/local/bin/wazuh-auto-response.py` |
| Alerts | `/var/ossec/logs/alerts/alerts.json` |
| AR Log | `/var/ossec/logs/active-responses.log` |

### Defense VM (192.168.122.10)
| File | Path |
|------|------|
| Flask App | `C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\app.py` |
| Login Page | `...\templates\login.html` |
| Auth Log | `...\auth.log` |
| Agent Config | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
