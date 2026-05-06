#!/usr/bin/env python3
"""
Wazuh Auto-Response Watcher
Monitors alerts.json for failed login alerts (rule 100101)
and auto-triggers the custom-firewall-drop AR script.
"""

import json
import subprocess
import time
import os
import sys

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
AR_SCRIPT = "/var/ossec/active-response/bin/custom-firewall-drop"
STATE_FILE = "/var/lib/wazuh-forwarder/ar-offset.txt"
BLOCKED_IPS_FILE = "/var/lib/wazuh-forwarder/blocked-ips.json"
COOLDOWN = 300  # seconds

def get_last_offset():
    try:
        with open(STATE_FILE, "r") as f:
            return int(f.read().strip())
    except:
        return 0

def save_offset(offset):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(str(offset))

def get_blocked_ips():
    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_blocked_ips(blocked):
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(blocked, f)

def is_blocked(ip):
    """Check if IP is already blocked in iptables"""
    try:
        result = subprocess.run(
            ["/usr/sbin/iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except:
        return False

def block_ip(ip, user):
    """Trigger AR script to block an IP"""
    try:
        # Whitelist check - never block our own IPs
        whitelist = ["192.168.122.1", "127.0.0.1"]
        if ip in whitelist:
            print(f"  SKIP: {ip} is whitelisted")
            return False

        # Check if already blocked
        if is_blocked(ip):
            print(f"  SKIP: {ip} already blocked in iptables")
            return False

        # Call AR script with plain text input
        result = subprocess.run(
            ["sudo", AR_SCRIPT],
            input=f"{ip} add\n",
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"  BLOCKED: {ip} (user: {user})")
            return True
        else:
            print(f"  FAILED: {ip} - {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"  ERROR: {ip} - {e}")
        return False

def main():
    print(f"Wazuh Auto-Response Watcher started")
    print(f"Monitoring: {ALERTS_FILE}")
    print(f"AR Script: {AR_SCRIPT}")
    print(f"Cooldown: {COOLDOWN}s")
    print("---")

    last_offset = get_last_offset()
    blocked_ips = get_blocked_ips()

    while True:
        try:
            current_size = os.path.getsize(ALERTS_FILE)
        except FileNotFoundError:
            time.sleep(5)
            continue

        if current_size <= last_offset:
            time.sleep(2)
            continue

        # Read new lines
        try:
            with open(ALERTS_FILE, "r") as f:
                f.seek(last_offset)
                new_content = f.read()
                last_offset = f.tell()
        except Exception as e:
            print(f"Error reading alerts: {e}")
            time.sleep(5)
            continue

        save_offset(last_offset)

        # Process each new line
        for line in new_content.strip().split("\n"):
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
            except:
                continue

            # Check if this is a failed login alert (rule 100101)
            rule = alert.get("rule", {})
            if rule.get("id") != "100101":
                continue

            data = alert.get("data", {})
            srcip = data.get("srcip", "")
            user = data.get("dstuser", "unknown")
            timestamp = alert.get("timestamp", "")

            if not srcip:
                continue

            print(f"[{timestamp}] Failed login from {srcip} (user: {user})")

            # Check cooldown
            now = time.time()
            if srcip in blocked_ips:
                last_blocked = blocked_ips[srcip]
                if now - last_blocked < COOLDOWN:
                    print(f"  COOLDOWN: {srcip} blocked {int(now - last_blocked)}s ago")
                    continue

            # Block the IP
            if block_ip(srcip, user):
                blocked_ips[srcip] = now
                save_blocked_ips(blocked_ips)

        time.sleep(2)

if __name__ == "__main__":
    main()
