# Attack Scenarios Replay Definitions

This directory contains scripted replay definitions for testing triage performance across 7 MITRE ATT&CK techniques (8 attack scenarios):

| File | Technique ID | Technique Name | Signal / Event Code | Expected Verdict |
|---|---|---|---|---|
| `attack_T1003.001_lsass_dump.json` | T1003.001 | OS Credential Dumping: LSASS Memory | Sysmon Event 10 (`rundll32.exe`, `comsvcs.dll`, mask `0x1fffff`) | **Escalate** |
| `attack_T1046_port_scan.json` | T1046 | Network Service Discovery | Suricata IDS (Inbound probe to DB port 1521) | **Escalate** |
| `attack_T1053.005_scheduled_task.json` | T1053.005 | Scheduled Task/Job: Scheduled Task | Sysmon Event 1 (`schtasks.exe` targeting AppData) | **Escalate** |
| `attack_T1055.001_dll_injection.json` | T1055.001 | Process Injection: DLL Injection | Sysmon Event 1 (`mavinject.exe` injecting payload DLL) | **Escalate** |
| `attack_T1059.001_powershell.json` | T1059.001 | Command and Scripting Interpreter: PowerShell | Sysmon Event 1 (Base64 encoded download cradle) | **Escalate** |
| `attack_T1071.001_1_c2_beacon.json` | T1071.001 | Application Layer Protocol: Web Protocols (C2) | Suricata IDS (Periodic HTTP C2 beaconing) | **Escalate** |
| `attack_T1071.001_2_script_outbound.json` | T1071.001 | Suspicious Script Outbound Network Connection | Sysmon Event 3 (Script interpreter socket connection) | **Escalate** |
| `attack_T1547.001_run_key.json` | T1547.001 | Registry Run Keys / Startup Folder | Sysmon Event 13 (HKCU Run key persistence) | **Escalate** |

