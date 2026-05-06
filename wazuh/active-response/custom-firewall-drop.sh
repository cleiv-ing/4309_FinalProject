#!/bin/bash
# custom-firewall-drop - Wrapper for Wazuh active response
# Blocks attacker IP using iptables
# Wazuh sends: srcip action (e.g., "192.168.122.1 add" or "192.168.122.1 delete")

LOG_FILE="/var/ossec/logs/active-responses.log"
IPTABLES="/usr/sbin/iptables"

# Read input from stdin
while read -r line; do
    # Parse input - expect "srcip action" or JSON with srcip field
    if echo "$line" | grep -q '"srcip"'; then
        # JSON input
        SRCIP=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('srcip',''))" 2>/dev/null)
    else
        # Plain text input: "srcip action"
        SRCIP=$(echo "$line" | awk '{print $1}')
    fi
    
    if [ -z "$SRCIP" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: ERROR - No srcip found" >> "$LOG_FILE"
        continue
    fi
    
    # Validate IP format
    if ! echo "$SRCIP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: ERROR - Invalid IP: $SRCIP" >> "$LOG_FILE"
        continue
    fi
    
    # Add iptables rule to block the IP
    $IPTABLES -A INPUT -s "$SRCIP" -j DROP 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: SUCCESS - Blocked $SRCIP" >> "$LOG_FILE"
    else
        echo "$(date '+%Y/%m/%d %H:%M:%S') custom-firewall-drop: FAILED - Could not block $SRCIP" >> "$LOG_FILE"
    fi
done

exit 0
