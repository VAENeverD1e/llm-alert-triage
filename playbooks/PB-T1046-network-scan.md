# Playbook - T1046: Network Service Discovery

| Field            | Value                                              |
|------------------|----------------------------------------------------|
| Technique        | T1046 - Network Service Discovery                  |
| Severity         | Medium                                             |
| Detection rule   | `Network Service Discovery (Suricata)`             |
| Primary signal   | Suricata IDS - Emerging Threats `*SCAN*` signature |
| Secondary signal | Sysmon Event ID 1 (scanner process creation)       |
| MITRE tactic     | Discovery (TA0007)                                 |

---

## What triggered this alert

Suricata matched one or more Emerging Threats scan signatures on the
monitored network interface, indicating that a host is actively probing
ports or services on other hosts in the subnet. This is a dual-layer
detection: Suricata catches the wire-level packets while Sysmon Event
ID 1 captures the scanning tool's process creation on the endpoint.

Network scanning is typically a post-initial-access activity - the
attacker is mapping the environment to find lateral movement targets.

---

## Triage steps

**Step 1 - Identify the scanner and target**

In Kibana, inspect the Suricata alert:

```
source.ip           ← scanning host
destination.ip      ← scanned target(s)
destination.port    ← which ports were probed?
rule.name           ← specific ET SCAN signature name
rule.category
@timestamp
```

Common ET SCAN signature names and their meaning:

| rule.name contains        | What it means                          |
|---------------------------|----------------------------------------|
| `ET SCAN Nmap`            | Nmap detected on the wire              |
| `ET SCAN XMAS`            | TCP XMAS scan (fin+psh+urg flags)      |
| `ET SCAN SYN`             | SYN scan (half-open port scan)         |
| `ET SCAN Potential SSH`   | SSH brute force / scan                 |
| `ET SCAN DB Ports`        | Database port enumeration (5432, 3306) |

**Step 2 - Identify the scanning process on the endpoint**

> **If the source IP is external** (not in your managed subnet), skip
> Steps 2–4. There is no endpoint to pivot to. Jump directly to
> containment: block the source IP at the perimeter firewall, check
> whether any scanned ports are externally exposed, and treat as
> reconnaissance against the perimeter.

If the source IP is a managed internal host, resolve it to a hostname
and pivot to Sysmon Event ID 1 near the alert timestamp:

```kql
host.name: "<source_hostname>" AND
event.code: 1 AND
process.name: ("nmap.exe" OR "nmap" OR "python.exe" OR "masscan.exe"
               OR "angry_ip_scanner.exe" OR "zenmap.exe") AND
@timestamp: [<alert_time - 2m> TO <alert_time + 2m>]
```

> **Note:** Sysmon Event ID 1 does not index endpoint IPs under
> `host.ip`. Pivot using `host.name` or `host.hostname`. Resolve the
> source IP from the Suricata alert to a hostname via your asset
> inventory before querying.

Also broaden to catch custom scanners:

```kql
host.name: "<source_hostname>" AND
event.code: 1 AND
process.command_line: (*scan* OR *port* OR *192.168* OR *-sS* OR *-sV*)
```

**Step 3 - Determine scan scope**

How many destination IPs were probed? Aggregate in Kibana Lens:

```
source.ip: "<scanner_ip>" AND
event.module: suricata AND event.kind: alert AND rule.name: *SCAN*
```

Group by `destination.ip` and `destination.port`.

- **Single target, few ports** → targeted reconnaissance
- **Subnet-wide scan** → mapping entire environment (post-breach behavior)
- **Single port across all hosts** → lateral movement target hunting
  (e.g. scanning for RDP :3389 or SMB :445)

**Step 4 - Establish whether the scan is authorized**

Check your authorized scanner list:

- Is the source IP a known vulnerability scanner (Nessus, Qualys)?
- Was a scan authorized in the change management system for this date?
- Is the source IP a security team workstation?

**Step 5 - Check for follow-on activity**

If the scan was not authorized, search for subsequent exploitation
attempts from the same source:

```kql
source.ip: "<scanner_ip>" AND
@timestamp: [<alert_time> TO <alert_time + 60m>] AND
event.module: suricata AND event.kind: alert AND
NOT rule.name: *SCAN*
```

---

## TP vs FP escalation criteria

**Treat as TRUE POSITIVE if any of the following:**

- Source IP is not a recognized authorized scanner
- The scan occurs outside business hours or during an incident
- The scan targets sensitive ports: 445 (SMB), 3389 (RDP),
  22 (SSH), 5985/5986 (WinRM) - lateral movement vectors
- The scan targets the Domain Controller IP
- Exploitation attempts follow the scan within the same session
- The scanning process was spawned from a suspicious parent
  (e.g. a browser, email client, or encoded PowerShell)

**Treat as FALSE POSITIVE if all of the following:**

- Source IP is a documented vulnerability scanner
- Scan is within an authorized maintenance window
- Scan targets match the documented scope for that scanner
- No exploitation activity follows

**Escalate immediately if:**

- Subnet-wide scan is followed by lateral movement (SMB/RDP connections
  to previously unvisited hosts)
- The scanning host is a workstation or server that has no reason to
  run network discovery tools
- The same scan pattern appears from multiple hosts simultaneously
  (worm-like self-propagation)

---

## Containment and response actions

**For confirmed TRUE POSITIVE (unauthorized scanner):**

1. **Block outbound traffic from the scanning host** at the network
   level (firewall rule or VLAN isolation) while investigation is
   ongoing. Do not isolate immediately if it disrupts the investigation
   - monitor first.

2. **Identify the scanning tool** from Sysmon Event ID 1 and determine
   how it arrived on the host (download event, email attachment, etc.).

3. **Kill the scanning process:**

   ```powershell
   Stop-Process -Name "<scanner_process_name>" -Force
   ```

4. **Remove the scanning tool:**

   ```powershell
   # Preserve first
   Copy-Item "<scanner_path>" -Destination "\\forensic-share\<case_id>\"
   Remove-Item "<scanner_path>" -Force
   ```

5. **Check for exploitation of discovered services** - if the scanner
   found open ports, assume the attacker now knows what to target.
   Prioritize review of the systems whose ports were probed.

6. **If the scan was system-wide**, treat the scanning host as
   potentially compromised and escalate to full incident response.

**For authorized scanner generating noise:**

1. Add the scanner's source IP to the detection rule exception list
   to reduce alert volume.
2. Document the exception with the scanner's name, IP, and owner.
3. Consider scoping the Suricata rule to exclude the known scanner
   subnet via `NOT source.ip: <scanner_ip>`.

**For lab environment (Atomic Red Team):**

No cleanup required - nmap and Python port scanner leave no persistent
artifacts. The scan itself was the event.

---

## Evidence collection checklist

- [ ] Suricata alert records - `source.ip`, `destination.ip`, `rule.name`
- [ ] List of all destination IPs and ports scanned
- [ ] Sysmon Event ID 1 - scanner process name and full command line
- [ ] Scanner process parent - how was it launched?
- [ ] `user.name` and `host.name` of the scanning endpoint
- [ ] `@timestamp` range of the scan activity
- [ ] Authorized scanner list - was this scanner authorized?
- [ ] Follow-on activity from the scanner IP (exploitation attempts)
- [ ] Screenshot of Kibana showing scan signature and source/dest IPs

---

## References

- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
- [Detection scenario README](../detection-scenarios/scenario6-T1046-network-scan/README.md)
- [Emerging Threats rules](https://rules.emergingthreats.net/)
- [KQL rule](../queries/T1046-network-scan-suricata.ndjson)
- [Sigma rule](../sigma/T1046-network-scan.yml)
