#!/usr/bin/env python3
"""Wazuh Alert Forwarder - reads alerts.json and pushes to OpenSearch via _bulk API"""
import json
import os
import time
import subprocess
from pathlib import Path

OPENSEARCH = "https://localhost:9200"
AUTH = ("admin", "admin")
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
INDEX_NAME = f"wazuh-alerts-4.x-{time.strftime('%Y.%m.%d')}"
LOG_FILE = "/var/log/wazuh-forwarder.log"
STATE_FILE = "/var/lib/wazuh-forwarder/last_offset"

def log(msg):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def get_last_offset():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                return int(f.read().strip())
    except:
        pass
    return 0

def save_offset(offset):
    Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(str(offset))

def forward_alerts():
    try:
        file_size = os.path.getsize(ALERTS_FILE)
    except:
        return

    last_offset = get_last_offset()

    if file_size <= last_offset:
        return

    log(f"New data: file_size={file_size}, last_offset={last_offset}")

    try:
        with open(ALERTS_FILE, "r") as f:
            f.seek(last_offset)
            data = f.read()
    except Exception as e:
        log(f"Error reading file: {e}")
        save_offset(file_size)
        return

    if not data.strip():
        save_offset(file_size)
        return

    # Parse newline-delimited JSON (NDJSON)
    alerts = []
    for line in data.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            alerts.append(alert)
        except json.JSONDecodeError as e:
            log(f"Skipping malformed line: {e}")
            continue

    if not alerts:
        log("No valid alerts parsed")
        save_offset(file_size)
        return

    log(f"Processing {len(alerts)} alerts...")

    # Build NDJSON bulk body
    bulk_lines = []
    for alert in alerts:
        alert_id = alert.get("id")
        if not alert_id:
            # Generate a unique ID from timestamp + rule id
            ts = alert.get("timestamp", "")
            rule_id = alert.get("rule", {}).get("id", "")
            alert_id = f"{ts}-{rule_id}"

        action_line = json.dumps({"index": {"_index": INDEX_NAME, "_id": str(alert_id)}})
        bulk_lines.append(action_line)
        bulk_lines.append(json.dumps(alert))

    if not bulk_lines:
        log("No valid alerts to forward")
        save_offset(file_size)
        return

    bulk_body = "\n".join(bulk_lines) + "\n"

    cmd = [
        "curl", "-sk", "-u", f"{AUTH[0]}:{AUTH[1]}",
        "-X", "POST", f"{OPENSEARCH}/_bulk",
        "-H", "Content-Type: application/x-ndjson",
        "--data-binary", "@-"
    ]

    proc = subprocess.run(cmd, input=bulk_body, capture_output=True, text=True)
    response = proc.stdout.strip()

    try:
        resp_json = json.loads(response)
        if resp_json.get("errors"):
            error_count = sum(1 for item in resp_json.get("items", []) if "error" in item.get("index", {}))
            log(f"PARTIAL: {len(alerts)} alerts, {error_count} errors")
        else:
            success_count = sum(1 for item in resp_json.get("items", []) if item.get("index", {}).get("status") in (200, 201))
            log(f"SUCCESS: Forwarded {success_count}/{len(alerts)} alerts")
    except:
        log(f"Response: {response[:200]}")

    save_offset(file_size)

def main():
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    log(f"=== Forwarder started (index: {INDEX_NAME}) ===")

    while True:
        try:
            forward_alerts()
        except Exception as e:
            log(f"Error: {e}")
        time.sleep(5)

if __name__ == "__main__":
    main()
