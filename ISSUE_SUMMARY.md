# CE 4309 Project - Issue Summary for Opencode

## Problem
Wazuh all-in-one VM consistently hangs/ becomes unresponsive under any alert processing load.

## VM Configuration
- 6 vCPU cores (host: Intel i7-12650H, 16 logical CPUs)
- 12GB RAM
- Ubuntu 22.04, Wazuh all-in-one v4.14.5
- Running via QEMU/KVM

## What We've Tried (ALL FAILED)
1. Reduced vCPUs from 8 to 6 → still hangs
2. Increased RAM from 8GB to 12GB → still hangs
3. Disabled dashboard during attacks → still hangs
4. Disabled Python forwarder → still hangs
5. Disabled auto-response watcher → still hangs
6. Disabled indexer-connector (already disabled via config) → still hangs
7. Disabled syscheckd → still hangs
8. Sent attacks slowly (3s apart) → still hangs
9. Sent just 1 attack → still hangs
10. Started dashboard alone (no attacks) → hangs
11. No SSH connections during attacks → hangs (just the agent forwarding causes it)

## Root Cause
The Wazuh all-in-one (OpenSearch + Wazuh manager + analysisd + remoted + db) saturates all 6 vCPUs when processing even a single alert. This causes:
- RCU (Read-Copy-Update) kernel thread starvation
- systemd watchdog timeouts (journald, logind, udevd all timeout)
- Complete system unresponsiveness

Evidence from `journalctl`:
```
rcu_sched kthread starved for 119544 jiffies
Unless rcu_sched kthread gets sufficient CPU time, OOM is now expected behavior
systemd-journald.service: Watchdog timeout (limit 3min)!
systemd-logind.service: Watchdog timeout (limit 3min)!
```

## What DOES Work
- VM at idle with dashboard: STABLE
- VM processing 0 alerts: STABLE
- Any alert processing: HANGS

## Detection Pipeline (works, but causes hang)
1. Attacker sends POST to Flask app on Windows VM (192.168.122.10:5000)
2. Flask writes to auth.log
3. Wazuh agent (ID 002) forwards events to manager (192.168.122.247:1514)
4. Manager decodes with cpp-bank decoder → extracts srcip, dstuser, cppbank_status
5. Rule 100101 fires on STATUS=FAILED
6. Alert written to /var/ossec/logs/alerts/alerts.json
7. OpenSearch indexes alert
→ VM hangs at step 4-7

## What We Need
A way to either:
A) Reduce CPU usage of Wazuh all-in-one during alert processing, OR
B) Offload some processing from the VM to the NixOS host

## Potential Solutions to Explore
1. **Reduce OpenSearch heap** from 2GB to 1GB (currently set in /etc/wazuh-indexer/jvm.options)
2. **Disable OpenSearch indexing entirely** - write alerts to file only, index after demo
3. **Use Wazuh manager without OpenSearch** - output alerts to file, use alternative indexer
4. **Split the architecture** - Wazuh manager on one VM, OpenSearch on another
5. **Use a lighter SIEM** - something less resource-intensive than Wazuh all-in-one
6. **Pre-generate all evidence** - run attacks before demo, capture screenshots, show static evidence

## Current State of Repo (branch: main)
- `README.md` - Complete setup guide
- `demo.sh` - Demo script (dashboard OFF during attacks, ON after)
- `tools/ai-soc-agent.py` - AI SOC Agent (runs on NixOS host, monitors OpenSearch)
- `tools/alert-indexer.py` - Lightweight alert indexer
- `Troy_Login_Attack_Simulation/` - Flask app source
- `wazuh/` - Decoder, rules, AR script, configs
- All commits pushed to main branch

## Key Files on Wazuh VM
- Decoder: /var/ossec/etc/decoders/0025-cpp-bank.xml
- Rules: /var/ossec/etc/rules/local_rules.xml
- AR Script: /var/ossec/active-response/bin/custom-firewall-drop
- AR Config: /var/ossec/etc/shared/ar.conf
- Alerts: /var/ossec/logs/alerts/alerts.json
- AR Log: /var/ossec/logs/active-responses.log

## Credentials
- Wazuh Dashboard: admin/admin
- OpenSearch: admin/admin
- Wazuh API: wazuh/wazuh
- Manager SSH: wazuhadmin/1747
- Defense VM SSH: defense/7471
- Flask app: bankuser/SecurePass123
