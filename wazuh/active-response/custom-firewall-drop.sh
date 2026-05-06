#!/bin/bash
# custom-firewall-drop - Wazuh active response script
# Blocks attacker IP using iptables
# Supports both plain text ("IP action") and Wazuh JSON alert format

LOG_FILE="/var/ossec/logs/active-responses.log"
IPTABLES="/usr/sbin/iptables"

# Read entire stdin at once
INPUT=$(cat)

# Try to extract srcip - support both plain text and JSON formats
SRCIP=""

# First, try plain text format: "IP action" (e.g., "192.168.122.1 add")
if echo "$INPUT" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
    SRCIP=$(echo "$INPUT" | awk '{print $1}')
else
    # Try JSON format (Wazuh auto-trigger sends full alert JSON)
    SRCIP=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Try nested path first: parameters.alert.data.srcip
    srcip = d.get('parameters', {}).get('alert', {}).get('data', {}).get('srcip', '')
    if not srcip:
        srcip = d.get('parameters', {}).get('alert', {}).get('srcip', '')
    if not srcip:
        srcip = d.get('srcip', '')
    print(srcip)
except:
    print('')
" 2>/dev/null)
fi

if [ -z "$SRCIP" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: ERROR - No srcip found" >> "$LOG_FILE"
    exit 1
fi

# Validate IP format
if ! echo "$SRCIP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: ERROR - Invalid IP: $SRCIP" >> "$LOG_FILE"
    exit 1
fi

# Check if already blocked
if $IPTABLES -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: SKIP - $SRCIP already blocked" >> "$LOG_FILE"
    exit 0
fi

# Block the IP
$IPTABLES -A INPUT -s "$SRCIP" -j DROP 2>/dev/null

if [ $? -eq 0 ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: SUCCESS - Blocked $SRCIP" >> "$LOG_FILE"
else
    echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: FAILED - Could not block $SRCIP" >> "$LOG_FILE"
    exit 1
fi

exit 0
