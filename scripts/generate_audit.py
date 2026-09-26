import json
import glob
import os

files = [
    ("T1003.001.json", "T1003.001: OS Credential Dumping (LSASS)"),
    ("T1046.json", "T1046: Network Service Discovery (Port Scan)"),
    ("T1053.005.json", "T1053.005: Scheduled Task Creation"),
    ("T1055.001.json", "T1055.001: DLL Injection via mavinject"),
    ("T1059.001.json", "T1059.001: Encoded PowerShell Execution"),
    ("T1071.001(1).json", "T1071.001(1): C2 Web Beaconing (Suricata)"),
    ("T1071.001(2).json", "T1071.001(2): Script Outbound Network (Sysmon)"),
    ("T1547.001.json", "T1547.001: Registry Run Key Persistence"),
]

samples_data = {}
for fname, title in files:
    path = os.path.join("docs", "samples", fname)
    with open(path, "r", encoding="utf-8") as fp:
        raw = json.load(fp)
    samples_data[fname] = raw.get("_source", raw)

def get_nested(d, path_list):
    cur = d
    for p in path_list:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur

def format_cell(present, path_str, val_str):
    if not present or val_str is None or val_str == "":
        return "❌ **ABSENT** (`-`)"
    val_clean = str(val_str).replace("\n", " ").replace("|", "\\|")
    if len(val_clean) > 40:
        val_clean = val_clean[:37] + "..."
    return f"✅ `{path_str}`<br>`{val_clean}`"

lines = []
lines.append("# Alert Schema Audit & Master Comparison\n")
lines.append("This document provides an exhaustive, field-by-field comparative audit across all 8 live SIEM alert samples in [`docs/samples/`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/). It maps the structural split between host-based Sysmon and network-based Suricata alerts, surfaces concrete query/field discrepancies against the SIEM rule definitions (`config/rules_tight.ndjson`), and formally establishes the field taxonomy for Phase 2 Context Enrichment.\n")

lines.append("---\n")
lines.append("## 1. High-Level Telemetry & Context Availability Matrix\n")
lines.append("| Sample File | Telemetry Source | Event Code | MITRE Threat Block | Host Name | User Name | Process | Parent Proc | Registry | Network |\n")
lines.append("|---|---|---|---|---|---|---|---|---|---|\n")

for fname, title in files:
    src = samples_data[fname]
    telem = src.get("event", {}).get("module", "unknown")
    code = str(src.get("event", {}).get("code", "-"))
    
    threat = src.get("kibana.alert.rule.threat") or src.get("kibana", {}).get("alert", {}).get("rule", {}).get("threat")
    threat_str = "None"
    if threat:
        tech = threat[0].get("technique", [{}])[0]
        t_id = tech.get("id", "")
        subs = tech.get("subtechnique", [])
        sub_id = subs[0].get("id") if subs else ""
        threat_str = f"{t_id}" + (f" ({sub_id})" if sub_id else " (No subtech)")

    host = "✅ `" + (src.get("host", {}).get("name") or src.get("host", {}).get("hostname") or "") + "`" if src.get("host") else "❌ ABSENT"
    user = "✅ `" + (src.get("user", {}).get("name") or "") + "`" if (src.get("user") and src.get("user", {}).get("name")) else ("⚠️ `id only`" if src.get("user") else "❌ ABSENT")
    proc = "✅ `" + src.get("process", {}).get("name") + "`" if "process" in src else "❌ ABSENT"
    parent = "✅ `" + src.get("process", {}).get("parent", {}).get("name") + "`" if ("process" in src and src.get("process", {}).get("parent")) else "❌ ABSENT"
    reg = "✅ Present" if "registry" in src else "❌ ABSENT"
    net = "✅ Present" if ("source" in src or "destination" in src or telem == "suricata") else "❌ ABSENT"

    lines.append(f"| [`{fname}`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/{fname}) | `{telem}` | `{code}` | `{threat_str}` | {host} | {user} | {proc} | {parent} | {reg} | {net} |\n")

lines.append("\n---\n")
lines.append("## 2. Master Detailed Comparison Tables\n")
lines.append("Each cell indicates: Status (`PRESENT` / `ABSENT`), Path (flat dotted key or nested JSON path), and the observed value.\n\n")

# Table 2.1: Envelope Fields
lines.append("### 2.1 Envelope Fields (Common Alert Header)\n")
lines.append("| Sample File | Alert UUID | Rule Name | Severity / Risk | Timestamp | Host Name | User Name | kibana.alert.reason |\n")
lines.append("|---|---|---|---|---|---|---|---|\n")

for fname, title in files:
    src = samples_data[fname]
    uuid_val = src.get("kibana.alert.uuid") or src.get("kibana", {}).get("alert", {}).get("uuid", "-")
    rule_val = src.get("kibana.alert.rule.name") or src.get("kibana", {}).get("alert", {}).get("rule", {}).get("name", "-")
    sev_val = f"{src.get('kibana.alert.severity', '-')}/{src.get('kibana.alert.risk_score', '-')}"
    ts_val = src.get("@timestamp", "-")
    host_val = src.get("host", {}).get("name") or (src.get("host", {}).get("hostname") if src.get("host") else None)
    user_val = src.get("user", {}).get("name") if src.get("user") else None
    reason_val = src.get("kibana.alert.reason")

    c_uuid = format_cell(True, "kibana.alert.uuid", uuid_val)
    c_rule = format_cell(True, "kibana.alert.rule.name", rule_val)
    c_sev = format_cell(True, "severity/risk", sev_val)
    c_ts = format_cell(True, "@timestamp", ts_val)
    c_host = format_cell(host_val is not None, "host.name", host_val)
    c_user = format_cell(user_val is not None, "user.name", user_val)
    c_reason = format_cell(reason_val is not None, "kibana.alert.reason", reason_val)

    lines.append(f"| **`{fname}`** | {c_uuid} | {c_rule} | {c_sev} | {c_ts} | {c_host} | {c_user} | {c_reason} |\n")

# Table 2.2: Process & Parent Process Context
lines.append("\n### 2.2 Process & Parent Process Context Fields\n")
lines.append("| Sample File | process.name | process.executable | process.command_line | process.pid | process.parent.name | process.parent.command_line | process.hash.sha256 |\n")
lines.append("|---|---|---|---|---|---|---|---|\n")

for fname, title in files:
    src = samples_data[fname]
    p = src.get("process")
    if p:
        p_name = p.get("name")
        p_exe = p.get("executable")
        p_cmd = p.get("command_line")
        p_pid = p.get("pid")
        parent = p.get("parent")
        par_name = parent.get("name") if parent else None
        par_cmd = parent.get("command_line") if parent else None
        p_sha = p.get("hash", {}).get("sha256")
    else:
        p_name = p_exe = p_cmd = p_pid = par_name = par_cmd = p_sha = None

    c_name = format_cell(p_name is not None, "process.name", p_name)
    c_exe = format_cell(p_exe is not None, "process.executable", p_exe)
    c_cmd = format_cell(p_cmd is not None, "process.command_line", p_cmd)
    c_pid = format_cell(p_pid is not None, "process.pid", p_pid)
    c_par_name = format_cell(par_name is not None, "process.parent.name", par_name)
    c_par_cmd = format_cell(par_cmd is not None, "process.parent.command_line", par_cmd)
    c_sha = format_cell(p_sha is not None, "process.hash.sha256", p_sha)

    lines.append(f"| **`{fname}`** | {c_name} | {c_exe} | {c_cmd} | {c_pid} | {c_par_name} | {c_par_cmd} | {c_sha} |\n")

# Table 2.3: Windows Event 10 / LSASS Access & Registry Context
lines.append("\n### 2.3 LSASS Access (Event 10) & Registry (Event 13) Context Fields\n")
lines.append("| Sample File | TargetImage (winlog) | GrantedAccess (winlog) | CallTrace (winlog) | SourceUser (winlog) | registry.path | registry.value | registry.data.strings |\n")
lines.append("|---|---|---|---|---|---|---|---|\n")

for fname, title in files:
    src = samples_data[fname]
    wdata = src.get("winlog", {}).get("event_data", {})
    t_img = wdata.get("TargetImage")
    g_acc = wdata.get("GrantedAccess")
    c_trc = wdata.get("CallTrace")
    s_usr = wdata.get("SourceUser")

    reg = src.get("registry", {})
    r_path = reg.get("path")
    r_val = reg.get("value")
    r_strings = reg.get("data", {}).get("strings")
    r_str_0 = r_strings[0] if r_strings else None

    c_t_img = format_cell(t_img is not None, "winlog.event_data.TargetImage", t_img)
    c_g_acc = format_cell(g_acc is not None, "winlog.event_data.GrantedAccess", g_acc)
    c_c_trc = format_cell(c_trc is not None, "winlog.event_data.CallTrace", c_trc)
    c_s_usr = format_cell(s_usr is not None, "winlog.event_data.SourceUser", s_usr)
    c_r_path = format_cell(r_path is not None, "registry.path", r_path)
    c_r_val = format_cell(r_val is not None, "registry.value", r_val)
    c_r_str = format_cell(r_str_0 is not None, "registry.data.strings[0]", r_str_0)

    lines.append(f"| **`{fname}`** | {c_t_img} | {c_g_acc} | {c_c_trc} | {c_s_usr} | {c_r_path} | {c_r_val} | {c_r_str} |\n")

# Table 2.4: Network & Suricata Context
lines.append("\n### 2.4 Network & Suricata IDS Context Fields\n")
lines.append("| Sample File | source.ip:port | destination.ip:port | network.protocol / transport | network.direction | user_agent.original | suricata.signature (rule.name) | suricata.category |\n")
lines.append("|---|---|---|---|---|---|---|---|\n")

for fname, title in files:
    src = samples_data[fname]
    s_ip = src.get("source", {}).get("ip") or (src.get("source", {}).get("address") if src.get("source") else None)
    s_pt = src.get("source", {}).get("port") if src.get("source") else None
    src_sock = f"{s_ip}:{s_pt}" if s_ip is not None else None

    d_ip = src.get("destination", {}).get("ip") or (src.get("destination", {}).get("address") if src.get("destination") else None)
    d_pt = src.get("destination", {}).get("port") if src.get("destination") else None
    dst_sock = f"{d_ip}:{d_pt}" if d_ip is not None else None

    proto = src.get("network", {}).get("protocol") or src.get("network", {}).get("transport")
    direction = src.get("network", {}).get("direction")
    ua = src.get("user_agent", {}).get("original")
    r_name = src.get("rule", {}).get("name") if src.get("event", {}).get("module") == "suricata" else None
    r_cat = src.get("rule", {}).get("category") if src.get("event", {}).get("module") == "suricata" else None

    c_src = format_cell(src_sock is not None, "source.ip:port", src_sock)
    c_dst = format_cell(dst_sock is not None, "destination.ip:port", dst_sock)
    c_proto = format_cell(proto is not None, "network.protocol", proto)
    c_dir = format_cell(direction is not None, "network.direction", direction)
    c_ua = format_cell(ua is not None, "user_agent.original", ua)
    c_sig = format_cell(r_name is not None, "rule.name", r_name)
    c_cat = format_cell(r_cat is not None, "rule.category", r_cat)

    lines.append(f"| **`{fname}`** | {c_src} | {c_dst} | {c_proto} | {c_dir} | {c_ua} | {c_sig} | {c_cat} |\n")

lines.append("\n---\n")
lines.append("## 3. Concrete Field-Name Mismatches & Detection Bugs Flagged\n\n")

lines.append("During this cross-sample comparison against the SIEM rule definitions in [`config/rules_tight.ndjson`](file:///c:/Users/Huy/Desktop/llm-alert-triage/config/rules_tight.ndjson) and [`normalized_alert_schema.py`](file:///c:/Users/Huy/Desktop/llm-alert-triage/normalized_alert_schema.py), the following **7 concrete discrepancies and bugs** were uncovered:\n\n")

lines.append("""### Bug 1: LSASS Source Image vs. Process Name Mismatch (T1003.001)
* **What `config/rules_tight.ndjson` assumes:**
  ```json
  {"rule_id": "T1003.001", "name": "LSASS Memory Dump Attempt", "exclusions": ["process.name: Taskmgr.exe", "user.name: AdminBackup"]}
  ```
* **What the live Kibana query actually runs:**
  ```text
  NOT (winlog.event_data.SourceImage: *taskmgr.exe AND winlog.event_data.GrantedAccess: ("0x1010" OR "0x1410"))
  ```
* **Discrepancy:** In raw Sysmon Event 10 logs, the source binary is stored in `winlog.event_data.SourceImage`. While Elastic Common Schema (ECS) creates a projected `process.name: rundll32.exe`, raw Windows queries filtering on `winlog.event_data.SourceImage` bypass ECS `process.name` filtering. If an agent checks `alert.process.name` against exclusions expecting `Taskmgr.exe` vs `*taskmgr.exe`, case-sensitivity or full path differences (`C:\\Windows\\System32\\Taskmgr.exe`) cause exclusion evaluation failure.

---

### Bug 2: Missing `user.name` on LSASS Alerts (T1003.001)
* **What `config/rules_tight.ndjson` assumes:**
  `"exclusions": ["user.name: AdminBackup"]`
* **What `normalized_alert_schema.py` does:**
  `user_name = src.get("user", {}).get("name")`
* **What the live alert actually contains (`docs/samples/T1003.001.json`):**
  `"user": {"id": "S-1-5-18"}` — **`user.name` is completely absent!**
  The actual username is located under:
  `winlog.event_data.SourceUser: "DESKTOP-THONLNR\\victim"` and `winlog.event_data.TargetUser: "NT AUTHORITY\\SYSTEM"`.
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
* **Fix required:** Parse subtechnique from `kibana.alert.rule.name` or `kibana.alert.rule.description` using regex `(T\\d{4}\\.\\d{3})` when `subtechnique` is empty.

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
* **Fix required:** Parent process for Event 3, 10, and 13 **must be classified as Enrichment-Only**, requiring the Fact-Finding Agent to perform a temporal join against process creation events (Event 1) using `process.pid` or `process.entity_id` within the $\\pm 5$ minute window.

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
""")

lines.append("\n---\n")
lines.append("## 4. Master Field Taxonomy & Classification\n\n")
lines.append("To support Phase 2 Item 2 (Context Enrichment), every field across the alert triage lifecycle is classified into one of three operational buckets:\n\n")

lines.append("1. **Envelope (Universal Alert Header):** Guaranteed to be present in SIEM alert hits across all telemetry modules. Handled directly by `NormalizedAlert` root attributes.\n")
lines.append("2. **Technique-Specific (Intra-Alert Context):** Present inside the alert hit itself, but only for specific telemetry families or event codes. Handled by optional sub-blocks.\n")
lines.append("3. **Enrichment-Only (Fact-Finding Agent Active Requirements):** Missing from the raw alert document entirely, but required for the Verdict Agent to determine benign vs. malicious activity. **The Fact-Finding Agent must actively query Elasticsearch context windows ($\\pm 5$ min), threat intel, or host asset stores to populate these.**\n\n")

lines.append("| Field Name | Taxonomy Bucket | Source Path / Extraction Method | Notes & Purpose |\n")
lines.append("|---|---|---|---|\n")

taxonomy = [
    ("alert_id", "Envelope", "kibana.alert.uuid", "Unique alert signal identifier"),
    ("rule_uuid", "Envelope", "kibana.alert.rule.uuid", "Kibana detection engine internal rule ID"),
    ("rule_id", "Envelope", "threat[0].technique[0].subtechnique[0].id (with fallback)", "MITRE ATT&CK technique / subtechnique ID"),
    ("rule_name", "Envelope", "kibana.alert.rule.name", "Human-readable detection rule title"),
    ("severity", "Envelope", "kibana.alert.severity", "Rule severity (low, medium, high, critical)"),
    ("risk_score", "Envelope", "kibana.alert.risk_score", "Kibana risk score (0-100)"),
    ("timestamp", "Envelope", "@timestamp", "Event trigger timestamp (ISO 8601 UTC)"),
    ("telemetry_source", "Envelope", "event.module ('windows' -> 'sysmon', 'suricata')", "Identifies telemetry origin"),
    ("event_code", "Envelope", "event.code / original_event.code", "Sysmon event code (1, 3, 10, 13) or None for Suricata"),
    ("reason", "Envelope", "kibana.alert.reason", "Elastic detection engine pre-computed summary string"),
    ("host_name", "Envelope*", "host.name / host.hostname", "Present in Sysmon; **Requires Enrichment for Suricata**"),
    ("user_name", "Envelope*", "user.name / winlog.event_data.SourceUser", "Present in Sysmon; **Absent in Suricata & Event 10 ECS**"),
    ("process.name", "Technique-Specific", "process.name (Sysmon 1, 3, 10, 13)", "Initiating process filename"),
    ("process.executable", "Technique-Specific", "process.executable (Sysmon 1, 3, 10, 13)", "Full binary path of initiating process"),
    ("process.command_line", "Technique-Specific", "process.command_line (Sysmon 1)", "Present for process creation; absent in 3, 10, 13"),
    ("process.pid", "Technique-Specific", "process.pid (Sysmon 1, 3, 10, 13)", "Operating system PID"),
    ("process.args", "Technique-Specific", "process.args (Sysmon 1)", "Parsed command line tokens"),
    ("process.hash.sha256", "Technique-Specific", "process.hash.sha256 (Sysmon 1)", "Executable cryptographic hash"),
    ("process.parent.name", "Technique-Specific*", "process.parent.name (Sysmon 1)", "**Only in Event 1; Enrichment-Only for Events 3, 10, 13**"),
    ("process.parent.executable", "Technique-Specific*", "process.parent.executable (Sysmon 1)", "**Only in Event 1; Enrichment-Only for Events 3, 10, 13**"),
    ("process.parent.command_line", "Technique-Specific*", "process.parent.command_line (Sysmon 1)", "**Only in Event 1; Enrichment-Only for Events 3, 10, 13**"),
    ("target_process_name", "Technique-Specific", "winlog.event_data.TargetImage (Sysmon 10)", "Victim process being accessed (e.g. lsass.exe)"),
    ("granted_access", "Technique-Specific", "winlog.event_data.GrantedAccess (Sysmon 10)", "Process access rights mask (e.g. 0x1FFFFF)"),
    ("call_trace", "Technique-Specific", "winlog.event_data.CallTrace (Sysmon 10)", "Stack trace DLL chain causing memory access"),
    ("registry.path", "Technique-Specific", "registry.path (Sysmon 13)", "Full registry key path modified"),
    ("registry.value", "Technique-Specific", "registry.value (Sysmon 13)", "Registry value name added/altered"),
    ("registry.data.strings", "Technique-Specific", "registry.data.strings[0] (Sysmon 13)", "Payload string stored in registry"),
    ("registry.hive", "Technique-Specific", "registry.hive (Sysmon 13)", "Registry hive (e.g. HKU, HKLM)"),
    ("source.ip / port", "Technique-Specific", "source.ip:source.port (Suricata, Sysmon 3)", "Source endpoint socket"),
    ("destination.ip / port", "Technique-Specific", "destination.ip:destination.port (Suricata, Sysmon 3)", "Destination endpoint socket"),
    ("network.protocol", "Technique-Specific", "network.protocol / transport (Suricata, Sysmon 3)", "Application layer protocol (http, dns) or transport"),
    ("network.direction", "Technique-Specific", "network.direction (Sysmon 3)", "Egress / Ingress indicator"),
    ("user_agent.original", "Technique-Specific", "user_agent.original (Suricata)", "HTTP client User-Agent string"),
    ("suricata_signature", "Technique-Specific", "rule.name (Suricata)", "IDS detection rule signature name"),
    ("suricata_category", "Technique-Specific", "rule.category (Suricata)", "Suricata alert classification category"),
    ("surrounding_process_tree", "Enrichment-Only", "Elasticsearch query: ±5 min window by host & parent PID", "Full process ancestry and sibling processes"),
    ("associated_network_conns", "Enrichment-Only", "Elasticsearch query: ±5 min window by PID & host", "Historical network flows initiated by process"),
    ("ip_threat_reputation", "Enrichment-Only", "Threat Intel lookup (e.g. VirusTotal, AbuseIPDB)", "External IP reputation, ASN, and geo-location"),
    ("user_privilege_context", "Enrichment-Only", "Active Directory / LDAP / local group query", "Determines if user is domain admin or service account"),
    ("endpoint_asset_criticality", "Enrichment-Only", "CMDB / Asset Inventory lookup", "Identifies if host is Domain Controller, SQL, or workstation"),
]

for fld, bkt, src_p, notes in taxonomy:
    bkt_fmt = f"**{bkt}**" if bkt == "Enrichment-Only" else f"`{bkt}`"
    lines.append(f"| `{fld}` | {bkt_fmt} | `{src_p}` | {notes} |\n")

content = "".join(lines)
with open("docs/alert-schema-audit.md", "w", encoding="utf-8") as fp:
    fp.write(content)

print("Generated docs/alert-schema-audit.md successfully. Total bytes:", len(content))
