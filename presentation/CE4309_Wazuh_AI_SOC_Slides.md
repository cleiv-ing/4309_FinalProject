---
marp: true
theme: default
paginate: true
title: CE 4309 Wazuh AI SOC Defense System
---

# CE 4309 Final Project

## Wazuh-Based Intrusion Detection and AI-Assisted Active Response

**Scenario:** CPP Bank failed login / brute-force attack simulation  
**Goal:** Detect attacks, visualize them in a SIEM dashboard, and block attacker IPs

---

# Project Objective

Build a working defensive monitoring system that demonstrates:

- A vulnerable-looking bank login simulation
- Host-based log collection from a Windows defender VM
- Wazuh decoding and rule-based detection
- OpenSearch/Wazuh Dashboard visualization
- AI-assisted brute-force analysis
- Automated IP blocking with active response

---

# High-Level System Design

```text
Attacker Laptop / VM
        |
        | HTTP POST failed logins
        v
Windows Defender VM: CPP Bank Flask App
        |
        | auth.log monitored by Wazuh Agent
        v
Wazuh Manager VM
        |
        | decoded alert + rule 100101
        v
OpenSearch + Wazuh Dashboard
        |
        | alert polling
        v
AI SOC Agent on NixOS Host
        |
        | SSH response actions
        v
Wazuh iptables + Windows Defender Firewall
```

---

# Network Topology

| Component | IP | Role |
|---|---:|---|
| NixOS host | `192.168.122.1` | Admin host + AI SOC agent |
| Windows defender VM | `192.168.122.10` | Flask bank app + Wazuh agent |
| Wazuh manager VM | `192.168.122.247` | Wazuh, OpenSearch, dashboard |
| Separate attacker | variable | Generates failed login attempts |

Important demo safety rule:

- `192.168.122.1` is protected because it is the admin/demo host.
- A separate attacker IP is blocked automatically.

---

# Attack Simulation

The bank app logs authentication attempts in a pipe-delimited format:

```text
2026-05-07 15:11:43 defense-vm IP=192.168.122.1 | USER=attacker | STATUS=FAILED | REASON=Invalid username or password
```

Example attack command:

```bash
curl -X POST http://192.168.122.10:5000/ \
  -d "username=attacker&password=wrong"
```

---

# Windows Defender VM

The Windows VM runs:

- Flask login simulation on TCP `5000`
- `auth.log` under the project directory
- Wazuh agent ID `002`

The Wazuh agent forwards the `auth.log` entries to the Wazuh manager.

This creates the host-to-SIEM pipeline used by the project.

---

# Wazuh Decoder

Custom decoder extracts the source IP, target user, and login status:

```xml
<decoder name="cpp-bank">
  <prematch>IP=</prematch>
  <regex>IP=(\S+) \| USER=(\S+) \| STATUS=(\S+)</regex>
  <order>srcip,user,cppbank_status</order>
</decoder>
```

Key extracted fields:

- `data.srcip`
- `data.dstuser`
- `data.cppbank_status`

---

# Wazuh Rules

Rule `100101` detects failed CPP Bank logins:

```xml
<rule id="100101" level="7">
  <if_sid>100100</if_sid>
  <match>STATUS=FAILED</match>
  <description>CPP Bank login failed</description>
</rule>
```

Alert output includes:

```json
"rule": { "id": "100101", "description": "CPP Bank login failed" },
"data": { "srcip": "192.168.122.1", "dstuser": "attacker", "cppbank_status": "FAILED" }
```

---

# Detection Pipeline

```text
Failed login request
  -> Flask writes auth.log
  -> Wazuh agent reads auth.log
  -> Wazuh manager receives event
  -> cpp-bank decoder extracts fields
  -> rule 100101 fires
  -> alert written to alerts.json
  -> forwarder indexes alert in OpenSearch
  -> Wazuh Dashboard displays event
```

Verified live:

- Fresh failed login alerts indexed in OpenSearch
- Dashboard shows failed attempts with `rule.id:100101`

---

# Dashboard and Search

Primary dashboard searches:

```text
rule.id:100101
```

Shows failed login detections.

```text
rule.id:100201
```

Shows AI SOC decisions.

The dashboard is used to show both detection and AI response decisions.

---

# Forwarder Reliability Fix

Problem found during testing:

- `alerts.json` can rotate/truncate after reboot or log maintenance.
- The forwarder's offset file could point beyond the end of the file.
- Result: no new alerts were indexed.

Fix implemented:

```python
if last_offset > file_size:
    log(f"Offset {last_offset} beyond alerts file size {file_size}; resetting to 0")
    last_offset = 0
    save_offset(0)
```

This restores real-time dashboard indexing after rotation.

---

# AI SOC Agent Purpose

The AI SOC agent runs on the NixOS host.

It does not replace Wazuh detection.

It performs higher-level analysis after Wazuh generates alerts:

- Poll OpenSearch for new Wazuh alerts
- Count failed attempts by source IP
- Detect brute force behavior
- Decide whether to block or skip
- Write an AI decision alert back to OpenSearch

---

# AI SOC Agent Logic

Threshold used in the demo:

```text
3+ failed logins from same srcip within 60 seconds
```

If threshold is met:

```text
BRUTE FORCE: <ip> (<count> attempts, users: <users>)
```

Then the agent either:

- blocks the attacker IP, or
- skips blocking if the IP is protected admin infrastructure.

---

# AI Decision Visibility

AI decisions are indexed back into OpenSearch as rule `100201`:

```json
"rule": { "id": "100201", "description": "AI SOC decision: blocked" },
"data": {
  "srcip": "192.168.122.250",
  "ai_action": "blocked",
  "ai_reason": "brute force threshold exceeded",
  "ai_attempts": 3
}
```

Dashboard search:

```text
rule.id:100201
```

---

# Active Response: Wazuh Manager

The custom active response script adds an iptables DROP rule:

```bash
echo "192.168.122.250 add" | sudo /var/ossec/active-response/bin/custom-firewall-drop
```

Verified block:

```text
DROP all -- 192.168.122.250 0.0.0.0/0
```

This proves the manager-side blocking path.

---

# Active Response: Windows Defender Firewall

For the strongest end-to-end defense, the AI agent also blocks on the Windows defender VM:

```text
netsh advfirewall firewall add rule
  name=AI_SOC_BLOCK_<IP>
  dir=in
  action=block
  remoteip=<attacker-ip>
  protocol=TCP
  localport=5000
```

This blocks the attacker from reaching the bank app itself.

---

# Verified Blocking Result

Tested with non-admin attacker IP `192.168.122.250`:

```text
BRUTE FORCE: 192.168.122.250
WINDOWS DEFENDER BLOCKED: 192.168.122.250 on TCP/5000
BLOCKED: 192.168.122.250
```

Windows firewall showed:

```text
RemoteIP: 192.168.122.250/32
Protocol: TCP
LocalPort: 5000
Action: Block
```

---

# Why the Admin Host Is Protected

In the VM-only demo, the NixOS host is also the attacker:

```text
192.168.122.1
```

If the AI agent blocked that IP, it would cut off:

- SSH access
- dashboard access
- demo control

So the AI agent protects that IP by default:

```text
PROTECTED: 192.168.122.1 matched protected/admin IP list
SKIPPED BLOCK
```

With a separate attacker laptop, this protection does not apply.

---

# Stability Challenges

Observed issue:

- Wazuh all-in-one VM could hang under load.
- OpenSearch, dashboard, Wazuh analysis, and custom scripts compete for limited CPU.

Mitigations:

- Reduced VM vCPU allocation to avoid host starvation.
- Stopped unnecessary response watchers during demo.
- Kept dashboard and forwarder active only in stable configuration.
- Fixed forwarder offset handling.

This is a realistic operational SIEM scaling problem.

---

# Final Demo Flow

Run setup if VM was rebooted:

```bash
bash /home/giovanniz/fix-wazuh.sh
```

Run the demo:

```bash
bash /home/giovanniz/demo.sh
```

What the demo verifies:

- Wazuh services running
- OpenSearch green
- Dashboard active
- Fresh failed logins indexed
- AI decision indexed
- Active response block verified

---

# Two-Computer Demo Flow

On the admin/NixOS host:

```bash
cd /var/lib/hermes-agent-official/workspace
python3 -u ai-soc-agent.py
```

On the attacker laptop:

```bash
curl -X POST http://192.168.122.10:5000/ \
  -d "username=attacker&password=wrong"
```

Repeat 3 times.

Expected result:

- Dashboard shows `rule.id:100101`
- AI agent shows brute force
- Dashboard shows `rule.id:100201`
- Windows firewall blocks attacker on TCP/5000

---

# Security Value Demonstrated

This project demonstrates:

- Endpoint log collection
- Custom decoder engineering
- Rule-based attack detection
- SIEM dashboard visualization
- AI-assisted behavior analysis
- Response automation
- Firewall enforcement at the defender host

It is a complete detect-and-respond security pipeline.

---

# Lessons Learned

- Detection correctness and operational stability are separate problems.
- SIEMs need resource planning under attack load.
- Active response must avoid blocking admin infrastructure.
- Dashboards are useful for visibility, but response needs automation.
- AI is most useful as an analysis and decision layer on top of SIEM alerts.

---

# Conclusion

The final system detects failed bank login attacks, indexes them into Wazuh/OpenSearch, visualizes them in the dashboard, and uses an AI SOC agent to decide and enforce blocking.

With a separate attacker IP, the system blocks the attacker automatically at the Windows Defender firewall and records the AI decision in the dashboard.

This completes the project goal: intrusion detection plus active response.
