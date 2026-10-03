# SOC Detection Lab - Incident Response Playbooks

> **Structured triage, escalation, and response procedures for each
> detection rule in this lab. One playbook per MITRE ATT&CK technique.**

---

## Purpose

Detection rules tell the SIEM what to fire on. Playbooks tell the
analyst what to do when the alert fires. Together they form a complete
detection-to-response workflow.

Each playbook covers four areas:

| Section                      | What it answers                                        |
|------------------------------|--------------------------------------------------------|
| **Triage steps**             | What to look at first, and in what order               |
| **TP vs FP criteria**        | How to classify the alert and when to escalate         |
| **Containment and response** | Concrete actions to take for a confirmed true positive |
| **Evidence checklist**       | What to collect before taking any remediation action   |

---

## Playbook index

| Playbook | Technique | Severity | Primary signal |
| ---------- | ----------- | ---------- | ---------------- |
| [PB-T1059.001](PB-T1059.001-powershell-fileless.md) | PowerShell Fileless Execution | High | Sysmon ID 1 |
| [PB-T1003.001](PB-T1003.001-lsass-dump.md) | LSASS Memory Dump | High | Sysmon ID 10 |
| [PB-T1547.001](PB-T1547.001-run-key-persistence.md) | Registry Run Key Persistence | Medium | Sysmon ID 13 |
| [PB-T1053.005](PB-T1053.005-scheduled-task.md) | Scheduled Task Persistence | High | Sysmon ID 1 + Win 4698 |
| [PB-T1055.001](PB-T1055.001-dll-injection.md) | DLL Injection via mavinject.exe | High | Sysmon ID 1 |
| [PB-T1046](PB-T1046-network-scan.md) | Network Service Discovery | Medium | Suricata IDS |
| [PB-T1071.001](PB-T1071.001-c2-beaconing.md) | C2 Beaconing via HTTP User Agents | High | Suricata + Sysmon ID 3 |

---

## Alert priority guidance

Not all alerts carry equal urgency. Use this triage order when multiple
alerts fire simultaneously:

```
PRIORITY 1 - Active intrusion indicators (respond within minutes)
  T1071.001  C2 Beaconing          ← host is already compromised
  T1003.001  LSASS Dump            ← credentials likely extracted

PRIORITY 2 - Persistence and privilege escalation (respond within the hour)
  T1055.001  DLL Injection         ← code executing inside trusted process
  T1053.005  Scheduled Task        ← attacker ensuring reboot survival
  T1547.001  Registry Run Key      ← attacker ensuring reboot survival

PRIORITY 3 - Reconnaissance and execution (investigate same day)
  T1059.001  Encoded PowerShell    ← may be initial access or lateral move
  T1046      Network Scan          ← pre-attack mapping, no exploit yet
```

---

## How to use these playbooks

**Step 1:** When an alert fires in Kibana, identify the technique from
the rule name and open the corresponding playbook.

**Step 2:** Work through the **Triage steps** in order. Do not skip to
containment before completing triage - premature action can destroy
forensic evidence and tip off the attacker.

**Step 3:** Apply the **TP vs FP criteria** to classify the alert.
If uncertain, treat as TP and escalate - the cost of a missed true
positive exceeds the cost of a false positive investigation.

**Step 4:** Complete the **Evidence checklist** before taking any
remediation action. Screenshots and exported records cannot be
recovered after host isolation or re-imaging.

**Step 5:** Execute **Containment and response** actions in order.

---

## Cross-references

Each playbook links back to:

- The detection scenario README (how the attack was simulated)
- The relevant threat hunt reports (gap analysis that shaped the rules)
- The KQL rule (`.ndjson` for Kibana import)
- The Sigma rule (`.yml` for SIEM-agnostic format)

---

## Lab environment note

All playbooks include a **"For lab environment"** section at the end
of the response actions. These steps cover Atomic Red Team cleanup
commands and are specific to this lab. In a production environment,
remove or replace these sections with organization-specific IR
procedures.
