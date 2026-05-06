#!/usr/bin/env python3
"""
AI SOC Agent - Final Version
Runs on NixOS host. Monitors Wazuh OpenSearch, detects brute force,
and blocks attackers via SSH to Wazuh manager.
"""

import json, subprocess, time, sys, signal, ssl, base64
from datetime import datetime, timedelta
from collections import defaultdict
import urllib.request

OPENSEARCH_URL  = "https://192.168.122.247:9200/"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "admin"
WAZUH_SSH       = "wazuh"
RULE_ID         = "100101"
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW    = 60
BLOCK_DURATION        = 300
OS_TIMEOUT   = 20
SSH_TIMEOUT  = 15
CHECK_INTERVAL = 5

blocked_ips = {}
ip_attempts = defaultdict(list)
last_check  = None

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def os_request(path, data=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"{OPENSEARCH_URL.rstrip('/')}/{path.lstrip('/')}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    auth = base64.b64encode(f"{OPENSEARCH_USER}:{OPENSEARCH_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=OS_TIMEOUT) as resp:
            return json.loads(resp.read())
    except:
        return None

def get_new_alerts():
    global last_check
    now = datetime.utcnow()
    time_from = (last_check or now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")
    result = os_request("wazuh-alerts-*/_search", {
        "query": {"bool": {"must": [
            {"term": {"rule.id": RULE_ID}},
            {"range": {"timestamp": {"gte": time_from}}}
        ]}},
        "size": 100, "sort": [{"timestamp": {"order": "asc"}}]
    })
    last_check = now
    if not result or "hits" not in result:
        return []
    return [h["_source"] for h in result["hits"]["hits"]]

def analyze(alerts):
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
    for alert in alerts:
        srcip = alert.get("data", {}).get("srcip", "")
        user = alert.get("data", {}).get("dstuser", "unknown")
        if not srcip or srcip == "127.0.0.1":
            continue
        try:
            ts = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00").split("+")[0])
            ip_attempts[srcip].append((ts, user))
        except:
            pass
    for ip in list(ip_attempts.keys()):
        ip_attempts[ip] = [(t, u) for t, u in ip_attempts[ip] if t.replace(tzinfo=None) > cutoff]
        if not ip_attempts[ip]:
            del ip_attempts[ip]
    return [(ip, len(a), list(set(u for _, u in a))) for ip, a in ip_attempts.items()
            if len(a) >= BRUTE_FORCE_THRESHOLD and ip not in blocked_ips]

def ssh_run(cmd):
    try:
        r = subprocess.run(["ssh", "-o", f"ConnectTimeout={SSH_TIMEOUT}",
                           "-o", "StrictHostKeyChecking=no", WAZUH_SSH, cmd],
                           capture_output=True, text=True, timeout=SSH_TIMEOUT + 5)
        return r.returncode == 0, r.stdout.strip()
    except:
        return False, ""

def block_ip(ip):
    ok, out = ssh_run(f"echo '{ip} add' | sudo /var/ossec/active-response/bin/custom-firewall-drop")
    if "SUCCESS" in out or "OK" in out or "blocked" in out.lower():
        return True
    ok, _ = ssh_run(f"sudo iptables -A INPUT -s {ip} -j DROP")
    return ok

def unblock_ip(ip):
    ssh_run(f"sudo iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
    blocked_ips.pop(ip, None)

def unblock_expired():
    for ip, ts in list(blocked_ips.items()):
        if time.time() - ts > BLOCK_DURATION:
            unblock_ip(ip)
            log(f"UNBLOCKED {ip}")

def cleanup(*_):
    log("Shutting down...")
    for ip in list(blocked_ips.keys()):
        unblock_ip(ip)
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("AI SOC Agent starting...")
    h = os_request("_cluster/health")
    log(f"OpenSearch: {h.get('status','?') if h else 'ERROR'}")
    if not h:
        sys.exit(1)
    ok, _ = ssh_run("echo ok")
    log(f"SSH: {'connected' if ok else 'FAILED'}")
    if not ok:
        sys.exit(1)
    log("Monitoring...\n")

    while True:
        try:
            unblock_expired()
            alerts = get_new_alerts()
            if alerts:
                for ip, count, users in analyze(alerts):
                    log(f"BRUTE FORCE: {ip} ({count} attempts, users: {', '.join(users)})")
                    if block_ip(ip):
                        blocked_ips[ip] = time.time()
                        log(f"BLOCKED: {ip}")
                    else:
                        log(f"FAILED to block {ip}")
                for ip, att in ip_attempts.items():
                    if ip not in blocked_ips and len(att) > 0:
                        log(f"  Tracking {ip}: {len(att)} attempts")
        except KeyboardInterrupt:
            cleanup()
        except Exception as e:
            log(f"Error: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
