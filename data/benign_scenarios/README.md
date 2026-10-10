# Benign Scenarios Noise Generators

This directory contains scripted benign telemetry noise mimicking everyday enterprise activity (admin maintenance, SCCM deployment, background telemetry, patch management) to evaluate false positive reduction across 7 MITRE ATT&CK techniques:

| File | Technique ID | Technique Name | Telemetry / Benign Context | Expected Verdict |
|---|---|---|---|---|
| `benign_T1003.001_lsass_wmi.json` | T1003.001 | OS Credential Dumping: LSASS Memory | Sysmon Event 10: `svchost.exe` WMI handle query, mask `0x1410`, CallTrace `cimwin32.dll` | **Close** |
| `benign_T1046_nessus_scan.json` | T1046 | Network Service Discovery | Suricata IDS: Authorized Nessus scanner from corporate security subnet (`10.0.0.50`) | **Close** |
| `benign_T1053.005_updater_task.json` | T1053.005 | Scheduled Task/Job: Scheduled Task | Sysmon Event 1: `schtasks.exe` registering Google Chrome / Defender daily updater task | **Close** |
| `benign_T1055.001_appv_virtualization.json` | T1055.001 | Process Injection: DLL Injection | Sysmon Event 1: `AppVClient.exe` injecting Office App-V virtualization subsystem DLL | **Close** |
| `benign_T1059.001_sccm_inventory.json` | T1059.001 | Command and Scripting Interpreter: PowerShell | Sysmon Event 1: SCCM (`CcmExec.exe`) running standard hardware inventory script | **Close** |
| `benign_T1071.001_1_onedrive_sync.json` | T1071.001 | Application Layer Protocol: Web Protocols (C2) | Suricata IDS: Legitimate Microsoft OneDrive cloud storage HTTPS heartbeat sync | **Close** |
| `benign_T1071.001_2_update_connection.json` | T1071.001 | Suspicious Script Outbound Network Connection | Sysmon Event 3: Windows Update service (`wuauserv`) outbound check to Microsoft CDN | **Close** |
| `benign_T1547.001_teams_run_key.json` | T1547.001 | Registry Run Keys / Startup Folder | Sysmon Event 13: Microsoft Teams registering auto-start under user HKCU Run key | **Close** |

