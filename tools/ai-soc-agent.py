#!/usr/bin/env python3
"""
AI SOC Agent - Final Version
Runs on NixOS host. Monitors Wazuh OpenSearch, detects brute force,
and blocks attackers via SSH to Wazuh manager.
"""

import json, os, subprocess, time, sys, signal, ssl, base64
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import urllib.request

OPENSEARCH_URL  = os.environ.get("AI_SOC_OPENSEARCH_URL", "https://192.168.122.247:9200/")
OPENSEARCH_USER = os.environ.get("AI_SOC_OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("AI_SOC_OPENSEARCH_PASS", "admin")
WAZUH_SSH       = os.environ.get("AI_SOC_WAZUH_SSH", "wazuh")
DEFENSE_SSH     = os.environ.get("AI_SOC_DEFENSE_SSH", "defense@192.168.122.10")
DEFENSE_APP_PORT = os.environ.get("AI_SOC_DEFENSE_APP_PORT", "5000")
RULE_ID         = "100101"
AI_DECISION_INDEX = os.environ.get("AI_SOC_DECISION_INDEX", "wazuh-alerts-4.x-2026.05.06")
AI_RULE_ID      = "100201"
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW    = 60
BLOCK_DURATION        = 300
OS_TIMEOUT   = 20
SSH_TIMEOUT  = 15
CHECK_INTERVAL = 5
PROTECTED_IPS = {ip.strip() for ip in os.environ.get("AI_SOC_PROTECTED_IPS", "192.168.122.1").split(",") if ip.strip()}

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
    except Exception as e:
        log(f"OpenSearch request failed: {e}")
        return None

def get_new_alerts():
    global last_check
    now = datetime.now(timezone.utc).replace(tzinfo=None)
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

def parse_alert_time(alert):
    ts = alert.get("@timestamp") or alert.get("timestamp", "")
    if not ts:
        return None
    ts = ts.replace("Z", "+00:00")
    # Python accepts -07:00 reliably; normalize Wazuh's -0700/+0000 form.
    if len(ts) >= 5 and (ts[-5] in "+-" and ts[-2] != ":"):
        ts = f"{ts[:-2]}:{ts[-2:]}"
    parsed = datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)

def analyze(alerts):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
    for alert in alerts:
        srcip = alert.get("data", {}).get("srcip", "")
        user = alert.get("data", {}).get("dstuser", "unknown")
        if not srcip or srcip == "127.0.0.1":
            continue
        try:
            ts = parse_alert_time(alert)
            if ts is None:
                continue
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
    return ssh_run_target(WAZUH_SSH, cmd)

def ssh_run_target(target, cmd):
    try:
        r = subprocess.run(["ssh", "-o", f"ConnectTimeout={SSH_TIMEOUT}",
                           "-o", "StrictHostKeyChecking=no", target, cmd],
                           capture_output=True, text=True, timeout=SSH_TIMEOUT + 5)
        return r.returncode == 0, r.stdout.strip()
    except:
        return False, ""

def block_ip(ip):
    if ip in PROTECTED_IPS:
        log(f"PROTECTED: {ip} matched protected/admin IP list; not blocking to avoid self-lockout")
        return None

    manager_ok = False
    windows_ok = False

    ok, out = ssh_run(f"echo '{ip} add' | sudo /var/ossec/active-response/bin/custom-firewall-drop")
    if "SUCCESS" in out or "OK" in out or "blocked" in out.lower():
        manager_ok = verify_block(ip)
    if ok and verify_block(ip):
        manager_ok = True
    if not manager_ok:
        ok, _ = ssh_run(f"sudo iptables -A INPUT -s {ip} -j DROP")
        manager_ok = ok and verify_block(ip)

    windows_ok = block_windows_defender(ip)
    return manager_ok or windows_ok

def block_windows_defender(ip):
    rule = "AI_SOC_BLOCK_" + ip.replace(".", "_")
    cmd = (
        f"netsh advfirewall firewall delete rule name={rule} >NUL 2>NUL & "
        f"netsh advfirewall firewall add rule name={rule} dir=in action=block "
        f"remoteip={ip} protocol=TCP localport={DEFENSE_APP_PORT}"
    )
    ok, out = ssh_run_target(DEFENSE_SSH, cmd)
    if ok and "Ok" in out:
        log(f"WINDOWS DEFENDER BLOCKED: {ip} on TCP/{DEFENSE_APP_PORT}")
        return True
    log(f"WINDOWS DEFENDER BLOCK FAILED: {ip}")
    return False

def verify_block(ip):
    ok, out = ssh_run(f"sudo iptables -C INPUT -s {ip} -j DROP && echo BLOCK_PRESENT")
    if ok and "BLOCK_PRESENT" in out:
        return True
    log(f"VERIFY FAILED: no iptables DROP rule found for {ip}")
    return False

def index_ai_decision(ip, action, reason, attempts=0, users=None):
    users = users or []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    doc = {
        "timestamp": timestamp,
        "rule": {
            "level": 10 if action == "blocked" else 7,
            "description": f"AI SOC decision: {action}",
            "id": AI_RULE_ID,
            "groups": ["ai-soc", "cpp-bank"]
        },
        "agent": {"id": "999", "name": "ai-soc-agent", "ip": "192.168.122.1"},
        "manager": {"name": "ce4309-wazuh"},
        "decoder": {"name": "ai-soc-agent"},
        "data": {
            "srcip": ip,
            "ai_action": action,
            "ai_reason": reason,
            "ai_attempts": attempts,
            "ai_users": ",".join(users)
        },
        "full_log": f"AI SOC {action}: {ip} - {reason} ({attempts} attempts; users={','.join(users)})",
        "location": "ai-soc-agent"
    }
    result = os_request(f"{AI_DECISION_INDEX}/_doc", doc)
    if result:
        os_request(f"{AI_DECISION_INDEX}/_refresh")
    else:
        log(f"AI decision indexing failed for {ip}: {action}")

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
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("AI SOC Agent starting...")
    h = os_request("_cluster/health")
    log(f"OpenSearch: {h.get('status','?') if h else 'ERROR'}")
    log(f"Protected IPs: {', '.join(sorted(PROTECTED_IPS)) if PROTECTED_IPS else '(none)'}")
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
                    result = block_ip(ip)
                    if result is True:
                        blocked_ips[ip] = time.time()
                        log(f"BLOCKED: {ip}")
                        index_ai_decision(ip, "blocked", "brute force threshold exceeded", count, users)
                    elif result is None:
                        log(f"SKIPPED BLOCK: {ip} is protected for this demo host")
                        index_ai_decision(ip, "protected_skip", "admin/demo host protected to avoid self-lockout", count, users)
                    else:
                        log(f"FAILED to block {ip}")
                        index_ai_decision(ip, "block_failed", "block command did not verify in iptables", count, users)
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
