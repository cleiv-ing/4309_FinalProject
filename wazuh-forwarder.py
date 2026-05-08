#!/usr/bin/env python3
import json
import os
import time
import subprocess
import tempfile
from pathlib import Path

OPENSEARCH = "https://localhost:9200"
AUTH = ("admin", "admin")
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
INDEX_NAME = os.environ.get("WAZUH_FORWARDER_INDEX", f"wazuh-alerts-4.x-{time.strftime('%Y.%m.%d')}")
LOG_FILE = "/var/log/wazuh-forwarder.log"
STATE_FILE = "/var/lib/wazuh-forwarder/offset.txt"

def log(msg):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    Path(LOG_FILE).touch(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")

def get_last_offset():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE) as f:
                content = f.read().strip()
                if content.isdigit():
                    return int(content)
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
    
    if last_offset > file_size:
        log(f"Offset {last_offset} beyond alerts file size {file_size}; resetting to 0")
        last_offset = 0
        save_offset(0)
    
    if file_size <= last_offset:
        return
    
    log(f"Processing {file_size - last_offset} new bytes...")
    
    try:
        with open(ALERTS_FILE, "r") as f:
            f.seek(last_offset)
            data = f.read()
    except Exception as e:
        log(f"Read error: {e}")
        save_offset(file_size)
        return
    
    if not data.strip():
        save_offset(file_size)
        return
    
    alerts = []
    for line in data.split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            if isinstance(alert, dict) and 'id' in alert:
                alerts.append(alert)
        except json.JSONDecodeError:
            continue
    
    if not alerts:
        log("No valid alerts found")
        save_offset(file_size)
        return
    
    log(f"Forwarding {len(alerts)} alerts in batches...")
    
    batch_size = 100
    success_count = 0
    error_count = 0
    
    for i in range(0, len(alerts), batch_size):
        batch = alerts[i:i+batch_size]
        
        bulk_lines = []
        for alert in batch:
            alert_id = alert.get("id")
            if not alert_id:
                continue
            action = json.dumps({"index": {"_index": INDEX_NAME, "_id": alert_id}})
            bulk_lines.append(action)
            bulk_lines.append(json.dumps(alert))
        
        if not bulk_lines:
            continue
        
        bulk_body = "\n".join(bulk_lines) + "\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ndjson', delete=False) as tmp:
            tmp.write(bulk_body)
            tmp_path = tmp.name
        
        try:
            cmd = [
                "curl", "-sk", "-u", f"{AUTH[0]}:{AUTH[1]}",
                "-X", "POST", f"{OPENSEARCH}/_bulk",
                "-H", "Content-Type: application/x-ndjson",
                "--data-binary", f"@{tmp_path}",
                "-w", "\\n%{http_code}"
            ]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            response = proc.stdout
            http_code = response.strip().split("\n")[-1] if response else "000"
            
            if http_code in ("200", "201"):
                success_count += len(batch)
            else:
                error_count += len(batch)
                log(f"Batch error HTTP {http_code}")
        except subprocess.TimeoutExpired:
            error_count += len(batch)
            log("Batch timeout")
        except Exception as e:
            error_count += len(batch)
            log(f"Batch exception: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    if success_count > 0:
        log(f"Done: {success_count} success, {error_count} errors")
    else:
        log("No successful forwards")
    
    save_offset(file_size)

def main():
    log(f"=== Forwarder started (index: {INDEX_NAME}) ===")
    
    while True:
        forward_alerts()
        time.sleep(3)

if __name__ == "__main__":
    main()
