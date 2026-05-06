# Wazuh Active Response Defense System

## Overview

Wazuh-based intrusion detection and active response system for the 4309 final project.

## Architecture

```
Attack Target (Flask App) 192.168.122.10
        ↓ (failed logins)
Defense VM (Windows + Wazuh Agent) 192.168.122.10
        ↓ (alerts)
Wazuh Manager (Linux) 192.168.122.247
        ↓ (indexes)
OpenSearch Dashboard https://192.168.122.247:9200
```

## Components

### Defense VM (Windows)
- IP: 192.168.122.10
- Flask app monitors auth.log
- Wazuh Agent sends logs to manager

### Wazuh Manager (Linux)  
- IP: 192.168.122.247
- Rule 100101: Detects CPP Bank login failures (level 7)
- Decoder extracts srcip from auth logs
- Active Response: custom-firewall-drop script

### OpenSearch
- URL: https://192.168.122.247:9200
- Auth: admin:admin
- Index: wazuh-alerts-4.x-YYYY.MM.DD

## Files on Wazuh Manager

### /var/ossec/etc/decoders/0025-cpp-bank.xml
```xml
<decoder name="cpp-bank-ip">
  <prematch>defense-vm IP=</prematch>
  <regex>IP=(\S+) | USER=(\S+) | STATUS=(\S+)</regex>
  <order>srcip</order>
</decoder>
```

### /var/ossec/active-response/bin/custom-firewall-drop
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

### /var/ossec/etc/shared/ar.conf
```
100101 - custom-firewall-drop - 300
```

### /usr/local/bin/wazuh-forwarder.py
Python script that replaces broken Filebeat. Reads alerts.json and indexes to OpenSearch.

## Test Commands

### Send Attack
```bash
for i in 1 2 3; do 
  curl -s -X POST "http://192.168.122.10:5000/" -d "username=bankuser&password=wrong$i"
done
```

### Check Detection
```bash
ssh wazuhadmin@192.168.122.247 "sudo grep 'Rule: 100101' /var/ossec/logs/alerts/alerts.log | tail -5"
```

### Check OpenSearch
```bash
ssh wazuhadmin@192.168.122.247 "curl -sk -u admin:admin 'https://localhost:9200/wazuh-alerts-4.x-2026.05.05/_count?q=rule.id:100101'"
```

### Manual Active Response Test
```bash
ssh wazuhadmin@192.168.122.247 "echo '192.168.122.99 add' | sudo /var/ossec/active-response/bin/custom-firewall-drop"
```

## Current Status (May 5, 2026)

- Detection: Working (45+ alerts with srcip)
- Indexing: Working (1400+ alerts in OpenSearch)
- Active Response: Works when triggered manually