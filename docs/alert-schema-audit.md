# Alert Schema Audit & Master Comparison
This document provides an exhaustive, field-by-field comparative audit across all 8 live SIEM alert samples in [`docs/samples/`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/). It maps the structural split between host-based Sysmon and network-based Suricata alerts, surfaces concrete query/field discrepancies against the SIEM rule definitions (`config/rules_tight.ndjson`), and formally establishes the field taxonomy for Phase 2 Context Enrichment.
---
## 1. High-Level Telemetry & Context Availability Matrix
| Sample File | Telemetry Source | Event Code | MITRE Threat Block | Host Name | User Name | Process | Parent Proc | Registry | Network |
|---|---|---|---|---|---|---|---|---|---|
| [`T1003.001.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1003.001.json) | `windows` | `10` | `T1003 (No subtech)` | ✅ `desktop-thonlnr` | ⚠️ `id only` | ✅ `rundll32.exe` | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT |
| [`T1046.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1046.json) | `suricata` | `-` | `T1046 (No subtech)` | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT | ✅ Present |
| [`T1053.005.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1053.005.json) | `windows` | `1` | `T1053 (T1053.005)` | ✅ `desktop-thonlnr` | ✅ `victim` | ✅ `schtasks.exe` | ✅ `cmd.exe` | ❌ ABSENT | ❌ ABSENT |
| [`T1055.001.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1055.001.json) | `windows` | `1` | `T1055 (T1055.001)` | ✅ `desktop-thonlnr` | ✅ `victim` | ✅ `mavinject.exe` | ✅ `powershell.exe` | ❌ ABSENT | ❌ ABSENT |
| [`T1059.001.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1059.001.json) | `windows` | `1` | `T1059 (T1059.001)` | ✅ `desktop-thonlnr` | ✅ `victim` | ✅ `powershell.exe` | ✅ `powershell.exe` | ❌ ABSENT | ❌ ABSENT |
| [`T1071.001(1).json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1071.001(1).json) | `suricata` | `-` | `T1071 (T1071.001)` | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT | ❌ ABSENT | ✅ Present |
| [`T1071.001(2).json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1071.001(2).json) | `windows` | `3` | `T1071 (T1071.001)` | ✅ `desktop-thonlnr` | ✅ `victim` | ✅ `powershell.exe` | ❌ ABSENT | ❌ ABSENT | ✅ Present |
| [`T1547.001.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/T1547.001.json) | `windows` | `13` | `T1547 (No subtech)` | ✅ `desktop-thonlnr` | ✅ `victim` | ✅ `reg.exe` | ❌ ABSENT | ✅ Present | ❌ ABSENT |

---
## 2. Master Detailed Comparison Tables
Each cell indicates: Status (`PRESENT` / `ABSENT`), Path (flat dotted key or nested JSON path), and the observed value.

### 2.1 Envelope Fields (Common Alert Header)
| Sample File | Alert UUID | Rule Name | Severity / Risk | Timestamp | Host Name | User Name | kibana.alert.reason |
|---|---|---|---|---|---|---|---|
| **`T1003.001.json`** | ✅ `kibana.alert.uuid`<br>`172e5b339f4fca65e8670c7b814ae4e4ec466...` | ✅ `kibana.alert.rule.name`<br>`LSASS Memory Access` | ✅ `severity/risk`<br>`high/73` | ✅ `@timestamp`<br>`2026-04-21T08:54:08.208Z` | ✅ `host.name`<br>`desktop-thonlnr` | ❌ **ABSENT** (`-`) | ✅ `kibana.alert.reason`<br>`process event with process rundll32.e...` |
| **`T1046.json`** | ✅ `kibana.alert.uuid`<br>`1cbfd3ccd90446ec9e6ed3d11220bb0a58b3d...` | ✅ `kibana.alert.rule.name`<br>`Network Service Discovery (Suricata)` | ✅ `severity/risk`<br>`medium/47` | ✅ `@timestamp`<br>`2026-07-27T09:00:00.122Z` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ✅ `kibana.alert.reason`<br>`network, intrusion_detection event wi...` |
| **`T1053.005.json`** | ✅ `kibana.alert.uuid`<br>`34282e80850e41edb3d8cbc4c41d916d4ce04...` | ✅ `kibana.alert.rule.name`<br>`Suspicious Scheduled Task Creation` | ✅ `severity/risk`<br>`high/73` | ✅ `@timestamp`<br>`2026-07-27T08:44:50.693Z` | ✅ `host.name`<br>`desktop-thonlnr` | ✅ `user.name`<br>`victim` | ✅ `kibana.alert.reason`<br>`process event with process schtasks.e...` |
| **`T1055.001.json`** | ✅ `kibana.alert.uuid`<br>`4384a8ca0f2a313f4970438ddd35599e3ebee...` | ✅ `kibana.alert.rule.name`<br>`DLL Injection via CreateRemoteThread` | ✅ `severity/risk`<br>`high/73` | ✅ `@timestamp`<br>`2026-07-27T08:54:59.986Z` | ✅ `host.name`<br>`desktop-thonlnr` | ✅ `user.name`<br>`victim` | ✅ `kibana.alert.reason`<br>`process event with process mavinject....` |
| **`T1059.001.json`** | ✅ `kibana.alert.uuid`<br>`537c522f7e23747508739dfaf73d6d71277d8...` | ✅ `kibana.alert.rule.name`<br>`Encoded PowerShell Execution Detection` | ✅ `severity/risk`<br>`high/73` | ✅ `@timestamp`<br>`2026-07-27T08:15:05.231Z` | ✅ `host.name`<br>`desktop-thonlnr` | ✅ `user.name`<br>`victim` | ✅ `kibana.alert.reason`<br>`process event with process powershell...` |
| **`T1071.001(1).json`** | ✅ `kibana.alert.uuid`<br>`71ae583efc0cb5014b1010147dea783f8439b...` | ✅ `kibana.alert.rule.name`<br>`Malicious HTTP User Agent (C2 Beaconing)` | ✅ `severity/risk`<br>`high/73` | ✅ `@timestamp`<br>`2026-04-25T10:39:20.726Z` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ✅ `kibana.alert.reason`<br>`network, intrusion_detection event wi...` |
| **`T1071.001(2).json`** | ✅ `kibana.alert.uuid`<br>`4b1822bde25a7261014118713e556803c9142...` | ✅ `kibana.alert.rule.name`<br>`Suspicious Script-Based Outbound Netw...` | ✅ `severity/risk`<br>`high/73` | ✅ `@timestamp`<br>`2026-07-27T09:10:00.128Z` | ✅ `host.name`<br>`desktop-thonlnr` | ✅ `user.name`<br>`victim` | ✅ `kibana.alert.reason`<br>`network event with process powershell...` |
| **`T1547.001.json`** | ✅ `kibana.alert.uuid`<br>`0bbb96f05b645b9e4b4452c0f93b7eabe4e35...` | ✅ `kibana.alert.rule.name`<br>`Registry Run Key Persistence` | ✅ `severity/risk`<br>`medium/47` | ✅ `@timestamp`<br>`2026-07-27T08:39:50.672Z` | ✅ `host.name`<br>`desktop-thonlnr` | ✅ `user.name`<br>`victim` | ✅ `kibana.alert.reason`<br>`configuration, registry event with pr...` |

### 2.2 Process & Parent Process Context Fields
| Sample File | process.name | process.executable | process.command_line | process.pid | process.parent.name | process.parent.command_line | process.hash.sha256 |
|---|---|---|---|---|---|---|---|
| **`T1003.001.json`** | ✅ `process.name`<br>`rundll32.exe` | ✅ `process.executable`<br>`C:\Windows\System32\rundll32.exe` | ❌ **ABSENT** (`-`) | ✅ `process.pid`<br>`4548` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1046.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1053.005.json`** | ✅ `process.name`<br>`schtasks.exe` | ✅ `process.executable`<br>`C:\Windows\System32\schtasks.exe` | ✅ `process.command_line`<br>`schtasks  /create /tn "T1053_005_OnSt...` | ✅ `process.pid`<br>`8144` | ✅ `process.parent.name`<br>`cmd.exe` | ✅ `process.parent.command_line`<br>`"cmd.exe" /c schtasks /create /tn "T1...` | ✅ `process.hash.sha256`<br>`9a80453518078badf0679b0cf30f50a83163e...` |
| **`T1055.001.json`** | ✅ `process.name`<br>`mavinject.exe` | ✅ `process.executable`<br>`C:\Windows\System32\mavinject.exe` | ✅ `process.command_line`<br>`"C:\Windows\system32\mavinject.exe" 4...` | ✅ `process.pid`<br>`7072` | ✅ `process.parent.name`<br>`powershell.exe` | ✅ `process.parent.command_line`<br>`"powershell.exe" & {$mypid = (Start-P...` | ✅ `process.hash.sha256`<br>`46a9c5234b3cc5352b5cc562b240aed83040c...` |
| **`T1059.001.json`** | ✅ `process.name`<br>`powershell.exe` | ✅ `process.executable`<br>`C:\Windows\System32\WindowsPowerShell...` | ✅ `process.command_line`<br>`"powershell.exe" & {# Encoded payload...` | ✅ `process.pid`<br>`8932` | ✅ `process.parent.name`<br>`powershell.exe` | ✅ `process.parent.command_line`<br>`"C:\Windows\System32\WindowsPowerShel...` | ✅ `process.hash.sha256`<br>`64dd55e1c2373deed25c2776f553c632e58c4...` |
| **`T1071.001(1).json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1071.001(2).json`** | ✅ `process.name`<br>`powershell.exe` | ✅ `process.executable`<br>`C:\Windows\System32\WindowsPowerShell...` | ❌ **ABSENT** (`-`) | ✅ `process.pid`<br>`63656` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1547.001.json`** | ✅ `process.name`<br>`reg.exe` | ✅ `process.executable`<br>`C:\Windows\system32\reg.exe` | ❌ **ABSENT** (`-`) | ✅ `process.pid`<br>`4164` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |

### 2.3 LSASS Access (Event 10) & Registry (Event 13) Context Fields
| Sample File | TargetImage (winlog) | GrantedAccess (winlog) | CallTrace (winlog) | SourceUser (winlog) | registry.path | registry.value | registry.data.strings |
|---|---|---|---|---|---|---|---|
| **`T1003.001.json`** | ✅ `winlog.event_data.TargetImage`<br>`C:\Windows\system32\lsass.exe` | ✅ `winlog.event_data.GrantedAccess`<br>`0x1fffff` | ✅ `winlog.event_data.CallTrace`<br>`C:\Windows\SYSTEM32\ntdll.dll+9d4a4\|...` | ✅ `winlog.event_data.SourceUser`<br>`DESKTOP-THONLNR\victim` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1046.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1053.005.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1055.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1059.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1071.001(1).json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1071.001(2).json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1547.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ✅ `registry.path`<br>`HKU\S-1-5-21-3933135484-4220633899-14...` | ✅ `registry.value`<br>`Atomic Red Team` | ✅ `registry.data.strings[0]`<br>`C:\Path\AtomicRedTeam.exe` |

### 2.4 Network & Suricata IDS Context Fields
| Sample File | source.ip:port | destination.ip:port | network.protocol / transport | network.direction | user_agent.original | suricata.signature (rule.name) | suricata.category |
|---|---|---|---|---|---|---|---|
| **`T1003.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1046.json`** | ✅ `source.ip:port`<br>`192.168.75.1:62917` | ✅ `destination.ip:port`<br>`192.168.75.11:1521` | ✅ `network.protocol`<br>`tcp` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ✅ `rule.name`<br>`ET SCAN Suspicious inbound to Oracle ...` | ✅ `rule.category`<br>`Potentially Bad Traffic` |
| **`T1053.005.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1055.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1059.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1071.001(1).json`** | ✅ `source.ip:port`<br>`192.168.75.11:8080` | ✅ `destination.ip:port`<br>`192.168.75.12:50708` | ✅ `network.protocol`<br>`http` | ❌ **ABSENT** (`-`) | ✅ `user_agent.original`<br>`*<\|>*` | ✅ `rule.name`<br>`ET INFO Python SimpleHTTP ServerBanner` | ✅ `rule.category`<br>`Misc activity` |
| **`T1071.001(2).json`** | ✅ `source.ip:port`<br>`192.168.31.132:51725` | ✅ `destination.ip:port`<br>`192.168.75.11:8080` | ✅ `network.protocol`<br>`tcp` | ✅ `network.direction`<br>`egress` | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |
| **`T1547.001.json`** | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) | ❌ **ABSENT** (`-`) |

---
## 3. Concrete Field-Name Mismatches & Detection Bugs Flagged

During this cross-sample comparison against the SIEM rule definitions in [`config/rules_tight.ndjson`](file:///c:/Users/Huy/Desktop/llm-alert-triage/config/rules_tight.ndjson) and [`normalized_alert_schema.py`](file:///c:/Users/Huy/Desktop/llm-alert-triage/normalized_alert_schema.py), the following **7 concrete discrepancies and bugs** were uncovered:

### Bug 1: LSASS Source Image vs. Process Name Mismatch (T1003.001)
* **What `config/rules_tight.ndjson` assumes:**
  ```json
  {"rule_id": "T1003.001", "name": "LSASS Memory Dump Attempt", "exclusions": ["process.name: Taskmgr.exe", "user.name: AdminBackup"]}
  ```
* **What the live Kibana query actually runs:**
  ```text
  NOT (winlog.event_data.SourceImage: *taskmgr.exe AND winlog.event_data.GrantedAccess: ("0x1010" OR "0x1410"))
  ```
* **Discrepancy:** In raw Sysmon Event 10 logs, the source binary is stored in `winlog.event_data.SourceImage`. While Elastic Common Schema (ECS) creates a projected `process.name: rundll32.exe`, raw Windows queries filtering on `winlog.event_data.SourceImage` bypass ECS `process.name` filtering. If an agent checks `alert.process.name` against exclusions expecting `Taskmgr.exe` vs `*taskmgr.exe`, case-sensitivity or full path differences (`C:\Windows\System32\Taskmgr.exe`) cause exclusion evaluation failure.

---

### Bug 2: Missing `user.name` on LSASS Alerts (T1003.001)
* **What `config/rules_tight.ndjson` assumes:**
  `"exclusions": ["user.name: AdminBackup"]`
* **What `normalized_alert_schema.py` does:**
  `user_name = src.get("user", {}).get("name")`
* **What the live alert actually contains (`docs/samples/T1003.001.json`):**
  `"user": {"id": "S-1-5-18"}` — **`user.name` is completely absent!**
  The actual username is located under:
  `winlog.event_data.SourceUser: "DESKTOP-THONLNR\victim"` and `winlog.event_data.TargetUser: "NT AUTHORITY\SYSTEM"`.
* **Impact:** `NormalizedAlert.user_name` resolves to `None`. Any rule exclusion checking `user.name` will silently fail to match, causing false positive escalations on admin backups.
* **Fix required:** Fallback in `NormalizedAlert.from_raw_alert`:
  ```python
  user_name = src.get("user", {}).get("name") or src.get("winlog", {}).get("event_data", {}).get("SourceUser")
  ```

---

### Bug 3: Subtechnique Truncation to Base Technique (T1003.001 & T1547.001)
* **What the system expects:** Rule IDs formatted with subtechniques (`T1003.001`, `T1547.001`).
* **What the live alerts contain:**
  In `T1003.001.json` and `T1547.001.json`, the `kibana.alert.rule.threat[0].technique[0]` object has:
  ```json
  "id": "T1003",
  "subtechnique": []
  ```
* **What `normalized_alert_schema.py` parses:**
  ```python
  subtech = technique.get("subtechnique") or []
  rule_id = subtech[0]["id"] if subtech else technique.get("id", "UNKNOWN")
  ```
* **Impact:** For these two alerts, `rule_id` is parsed as `"T1003"` and `"T1547"` rather than `"T1003.001"` and `"T1547.001"`. This breaks matching against `config/rules_tight.ndjson` and playbook retrieval in `integrations/playbook_retriever.py`.
* **Fix required:** Parse subtechnique from `kibana.alert.rule.name` or `kibana.alert.rule.description` using regex `(T\d{4}\.\d{3})` when `subtechnique` is empty.

---

### Bug 4: Complete Absence of Endpoint Hostname in Suricata Alerts (T1046 & T1071.001(1))
* **Observed Data:** In both Suricata alerts, the top-level `host` key is `None`. Network wire sniffers only record IP addresses (`source.ip: 192.168.75.11`, `destination.ip: 192.168.75.12`), with no endpoint telemetry agent attached.
* **Impact:** `NormalizedAlert.host_name` is `None`. Any downstream prompt or query assuming a valid `host_name` crashes or queries for literal `None`.
* **Fix required:** Fact-Finding Agent must treat host resolution as an active enrichment step (resolving internal IP `192.168.75.11` to `desktop-thonlnr` via asset logs or DHCP events).

---

### Bug 5: Parent Process Blindspot in Events 3, 10, and 13
* **Observed Data:**
  * Only Event 1 (`T1053.005`, `T1055.001`, `T1059.001`) contains `process.parent.*` inside the alert document.
  * Sysmon Event 3 (Network socket - `T1071.001(2)`), Event 10 (Process access - `T1003.001`), and Event 13 (Registry modification - `T1547.001`) contain **no parent process data**.
* **Impact:** In `agent/fact_finding/collector.py`, `has_anomalous_parent_process` cannot be answered from the alert document alone for these techniques.
* **Fix required:** Parent process for Event 3, 10, and 13 **must be classified as Enrichment-Only**, requiring the Fact-Finding Agent to perform a temporal join against process creation events (Event 1) using `process.pid` or `process.entity_id` within the $\pm 5$ minute window.

---

### Bug 6: Network Direction Missing in Suricata Alerts
* **What `config/rules_tight.ndjson` / schema expects:** `network.direction: "egress"`.
* **Observed Data:**
  * Sysmon Event 3 (`T1071.001(2)`) populates `network.direction: "egress"`.
  * Suricata alerts (`T1046`, `T1071.001(1)`) have `network.direction: None`. Instead, direction must be inferred by comparing `source.ip` and `destination.ip` against RFC1918 private subnets.

---

### Bug 7: Sysmon Rule Tagging Mismatched with Suricata Signatures
* **Observed Data:** In `T1547.001.json`, the alert contains `rule.name: "T1060,RunKey"`.
* **What happened:** In `normalized_alert_schema.py:L170`, `suricata_signature=rule_block.get("name")`. If `rule.name` is present in a Sysmon alert, the schema risks conflating internal Sysmon config rule tags with Suricata IDS signatures.
* **Fix required:** Only populate `suricata_signature` when `telemetry_source == "suricata"`.

---
## 4. Master Field Taxonomy & Classification

To support Phase 2 Item 2 (Context Enrichment), every field across the alert triage lifecycle is classified into one of three operational buckets:

1. **Envelope (Universal Alert Header):** Guaranteed to be present in SIEM alert hits across all telemetry modules. Handled directly by `NormalizedAlert` root attributes.
2. **Technique-Specific (Intra-Alert Context):** Present inside the alert hit itself, but only for specific telemetry families or event codes. Handled by optional sub-blocks.
3. **Enrichment-Only (Fact-Finding Agent Active Requirements):** Missing from the raw alert document entirely, but required for the Verdict Agent to determine benign vs. malicious activity. **The Fact-Finding Agent must actively query Elasticsearch context windows ($\pm 5$ min), threat intel, or host asset stores to populate these.**

| Field Name | Taxonomy Bucket | Source Path / Extraction Method | Notes & Purpose |
|---|---|---|---|
| `alert_id` | `Envelope` | `kibana.alert.uuid` | Unique alert signal identifier |
| `rule_uuid` | `Envelope` | `kibana.alert.rule.uuid` | Kibana detection engine internal rule ID |
| `rule_id` | `Envelope` | `threat[0].technique[0].subtechnique[0].id (with fallback)` | MITRE ATT&CK technique / subtechnique ID |
| `rule_name` | `Envelope` | `kibana.alert.rule.name` | Human-readable detection rule title |
| `severity` | `Envelope` | `kibana.alert.severity` | Rule severity (low, medium, high, critical) |
| `risk_score` | `Envelope` | `kibana.alert.risk_score` | Kibana risk score (0-100) |
| `timestamp` | `Envelope` | `@timestamp` | Event trigger timestamp (ISO 8601 UTC) |
| `telemetry_source` | `Envelope` | `event.module ('windows' -> 'sysmon', 'suricata')` | Identifies telemetry origin |
| `event_code` | `Envelope` | `event.code / original_event.code` | Sysmon event code (1, 3, 10, 13) or None for Suricata |
| `reason` | `Envelope` | `kibana.alert.reason` | Elastic detection engine pre-computed summary string |
| `host_name` | `Envelope*` | `host.name / host.hostname` | Present in Sysmon; **Requires Enrichment for Suricata** |
| `user_name` | `Envelope*` | `user.name / winlog.event_data.SourceUser` | Present in Sysmon; **Absent in Suricata & Event 10 ECS** |
| `process.name` | `Technique-Specific` | `process.name (Sysmon 1, 3, 10, 13)` | Initiating process filename |
| `process.executable` | `Technique-Specific` | `process.executable (Sysmon 1, 3, 10, 13)` | Full binary path of initiating process |
| `process.command_line` | `Technique-Specific` | `process.command_line (Sysmon 1)` | Present for process creation; absent in 3, 10, 13 |
| `process.pid` | `Technique-Specific` | `process.pid (Sysmon 1, 3, 10, 13)` | Operating system PID |
| `process.args` | `Technique-Specific` | `process.args (Sysmon 1)` | Parsed command line tokens |
| `process.hash.sha256` | `Technique-Specific` | `process.hash.sha256 (Sysmon 1)` | Executable cryptographic hash |
| `process.parent.name` | `Technique-Specific*` | `process.parent.name (Sysmon 1)` | **Only in Event 1; Enrichment-Only for Events 3, 10, 13** |
| `process.parent.executable` | `Technique-Specific*` | `process.parent.executable (Sysmon 1)` | **Only in Event 1; Enrichment-Only for Events 3, 10, 13** |
| `process.parent.command_line` | `Technique-Specific*` | `process.parent.command_line (Sysmon 1)` | **Only in Event 1; Enrichment-Only for Events 3, 10, 13** |
| `target_process_name` | `Technique-Specific` | `winlog.event_data.TargetImage (Sysmon 10)` | Victim process being accessed (e.g. lsass.exe) |
| `granted_access` | `Technique-Specific` | `winlog.event_data.GrantedAccess (Sysmon 10)` | Process access rights mask (e.g. 0x1FFFFF) |
| `call_trace` | `Technique-Specific` | `winlog.event_data.CallTrace (Sysmon 10)` | Stack trace DLL chain causing memory access |
| `registry.path` | `Technique-Specific` | `registry.path (Sysmon 13)` | Full registry key path modified |
| `registry.value` | `Technique-Specific` | `registry.value (Sysmon 13)` | Registry value name added/altered |
| `registry.data.strings` | `Technique-Specific` | `registry.data.strings[0] (Sysmon 13)` | Payload string stored in registry |
| `registry.hive` | `Technique-Specific` | `registry.hive (Sysmon 13)` | Registry hive (e.g. HKU, HKLM) |
| `source.ip / port` | `Technique-Specific` | `source.ip:source.port (Suricata, Sysmon 3)` | Source endpoint socket |
| `destination.ip / port` | `Technique-Specific` | `destination.ip:destination.port (Suricata, Sysmon 3)` | Destination endpoint socket |
| `network.protocol` | `Technique-Specific` | `network.protocol / transport (Suricata, Sysmon 3)` | Application layer protocol (http, dns) or transport |
| `network.direction` | `Technique-Specific` | `network.direction (Sysmon 3)` | Egress / Ingress indicator |
| `user_agent.original` | `Technique-Specific` | `user_agent.original (Suricata)` | HTTP client User-Agent string |
| `suricata_signature` | `Technique-Specific` | `rule.name (Suricata)` | IDS detection rule signature name |
| `suricata_category` | `Technique-Specific` | `rule.category (Suricata)` | Suricata alert classification category |
| `surrounding_process_tree` | **Enrichment-Only** | `Elasticsearch query: ±5 min window by host & parent PID` | Full process ancestry and sibling processes |
| `associated_network_conns` | **Enrichment-Only** | `Elasticsearch query: ±5 min window by PID & host` | Historical network flows initiated by process |
| `ip_threat_reputation` | **Enrichment-Only** | `Threat Intel lookup (e.g. VirusTotal, AbuseIPDB)` | External IP reputation, ASN, and geo-location |
| `user_privilege_context` | **Enrichment-Only** | `Active Directory / LDAP / local group query` | Determines if user is domain admin or service account |
| `endpoint_asset_criticality` | **Enrichment-Only** | `CMDB / Asset Inventory lookup` | Identifies if host is Domain Controller, SQL, or workstation |
