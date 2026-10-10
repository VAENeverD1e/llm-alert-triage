"""
Generate Benchmark Dataset for LLM Alert Triage Evaluation.
Populates:
  - data/attack_scenarios/ (from docs/samples/ raw SIEM exports)
  - data/benign_scenarios/ (realistic false positive / benign alerts)
  - data/ground_truth.jsonl (16 ground-truth labeled scenarios for Replay Harness)
"""
import os
import sys
import json
import shutil
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.schemas.triage_schema import (
    NormalizedAlert,
    ProcessInfo,
    ProcessContext,
    RegistryContext,
    NetworkContext,
)

ATTACK_DIR = "data/attack_scenarios"
BENIGN_DIR = "data/benign_scenarios"
GROUND_TRUTH_PATH = "data/ground_truth.jsonl"
SAMPLES_DIR = "docs/samples"


def setup_attack_scenarios() -> List[Dict[str, Any]]:
    os.makedirs(ATTACK_DIR, exist_ok=True)

    attack_mapping = [
        {
            "src": "T1003.001.json",
            "dst": "attack_T1003.001_lsass_dump.json",
            "alert_id": "ATK-T1003.001",
            "technique_id": "T1003.001",
            "technique_name": "OS Credential Dumping: LSASS Memory",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "LSASS memory access via rundll32.exe and comsvcs.dll MiniDump (access mask 0x1fffff)."
        },
        {
            "src": "T1046.json",
            "dst": "attack_T1046_port_scan.json",
            "alert_id": "ATK-T1046",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "Suricata alert on inbound port scan against Oracle DB port 1521 from unverified source IP."
        },
        {
            "src": "T1053.005.json",
            "dst": "attack_T1053.005_scheduled_task.json",
            "alert_id": "ATK-T1053.005",
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task/Job: Scheduled Task",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "schtasks.exe creating scheduled task targeting cmd.exe under user AppData for persistence."
        },
        {
            "src": "T1055.001.json",
            "dst": "attack_T1055.001_dll_injection.json",
            "alert_id": "ATK-T1055.001",
            "technique_id": "T1055.001",
            "technique_name": "Process Injection: Dynamic-link Library Injection",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "Process injection via mavinject.exe injecting suspicious DLL into target process."
        },
        {
            "src": "T1059.001.json",
            "dst": "attack_T1059.001_powershell.json",
            "alert_id": "ATK-T1059.001",
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "Base64 encoded PowerShell execution downloading secondary payload from untrusted IP."
        },
        {
            "src": "T1071.001(1).json",
            "dst": "attack_T1071.001_1_c2_beacon.json",
            "alert_id": "ATK-T1071.001-1",
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols (C2)",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "Suricata alert detecting periodic HTTP C2 beaconing with abnormal user-agent."
        },
        {
            "src": "T1071.001(2).json",
            "dst": "attack_T1071.001_2_script_outbound.json",
            "alert_id": "ATK-T1071.001-2",
            "technique_id": "T1071.001",
            "technique_name": "Suspicious Script Outbound Network Connection",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "Script interpreter initiating anomalous outbound socket connection to external untrusted IP."
        },
        {
            "src": "T1547.001.json",
            "dst": "attack_T1547.001_run_key.json",
            "alert_id": "ATK-T1547.001",
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys / Startup Folder",
            "expected_verdict": "Escalate",
            "scenario_type": "attack",
            "notes": "Sysmon Event 13: Modification of HKCU Run key to achieve reboot persistence."
        },
    ]

    records = []
    for item in attack_mapping:
        src_path = os.path.join(SAMPLES_DIR, item["src"])
        dst_path = os.path.join(ATTACK_DIR, item["dst"])
        if os.path.exists(src_path):
            shutil.copyfile(src_path, dst_path)
            print(f"[+] Copied {src_path} -> {dst_path}")
        else:
            print(f"[!] Warning: Source sample {src_path} not found!")

        records.append({
            "alert_id": item["alert_id"],
            "file_path": dst_path.replace("\\", "/"),
            "technique_id": item["technique_id"],
            "technique_name": item["technique_name"],
            "expected_verdict": item["expected_verdict"],
            "scenario_type": item["scenario_type"],
            "notes": item["notes"]
        })
    return records


def setup_benign_scenarios() -> List[Dict[str, Any]]:
    os.makedirs(BENIGN_DIR, exist_ok=True)

    benign_definitions = [
        {
            "filename": "benign_T1003.001_lsass_wmi.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1003.001",
                rule_uuid="bng-uuid-1003",
                rule_id="T1003.001",
                rule_name="LSASS Memory Access",
                severity="low",
                risk_score=21,
                timestamp="2026-10-10T08:00:00Z",
                host_name="desktop-thonlnr",
                user_name=r"NT AUTHORITY\SYSTEM",
                reason="Routine WMI host query accessing LSASS process space",
                telemetry_source="sysmon",
                event_code="10",
                process_context=ProcessContext(
                    process=ProcessInfo(
                        name="svchost.exe",
                        executable=r"C:\Windows\System32\svchost.exe",
                        command_line=r"C:\Windows\system32\svchost.exe -k DcomLaunch -p",
                        pid=944,
                    ),
                    target_process_name=r"C:\Windows\System32\lsass.exe",
                    granted_access="0x1410",
                    call_trace=r"C:\Windows\System32\cimwin32.dll+1a2b3|C:\Windows\System32\wbem\fastprox.dll+45c8",
                ),
            ),
            "technique_name": "OS Credential Dumping: LSASS Memory",
            "notes": "Routine WMI process handle query via svchost.exe (mask 0x1410, CallTrace contains cimwin32.dll - standard FP exclusion)."
        },
        {
            "filename": "benign_T1046_nessus_scan.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1046",
                rule_uuid="bng-uuid-1046",
                rule_id="T1046",
                rule_name="Network Service Scanning",
                severity="low",
                risk_score=25,
                timestamp="2026-10-10T08:05:00Z",
                host_name="sec-scanner-01",
                user_name="svc-security",
                reason="Authorized monthly internal vulnerability assessment scan",
                telemetry_source="suricata",
                event_code=None,
                network_context=NetworkContext(
                    source_ip="10.0.0.50",
                    source_port=49152,
                    destination_ip="10.0.0.10",
                    destination_port=80,
                    protocol="tcp",
                    direction="ingress",
                    user_agent="Mozilla/5.0 (compatible; Nessus Vulnerability Scanner)",
                    suricata_signature="ET INFO Authorized Security Vulnerability Scan in progress",
                    suricata_category="Potential Corporate Scanner",
                ),
            ),
            "technique_name": "Network Service Discovery",
            "notes": "Scheduled internal vulnerability scan from whitelisted security subnet (10.0.0.50) during authorized maintenance window."
        },
        {
            "filename": "benign_T1053.005_updater_task.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1053.005",
                rule_uuid="bng-uuid-1053",
                rule_id="T1053.005",
                rule_name="Scheduled Task Creation",
                severity="low",
                risk_score=20,
                timestamp="2026-10-10T08:10:00Z",
                host_name="desktop-thonlnr",
                user_name=r"NT AUTHORITY\SYSTEM",
                reason="Routine software auto-update task registration",
                telemetry_source="sysmon",
                event_code="1",
                process_context=ProcessContext(
                    process=ProcessInfo(
                        name="schtasks.exe",
                        executable=r"C:\Windows\System32\schtasks.exe",
                        command_line=r'schtasks.exe /create /tn "GoogleUpdateTaskMachineUA" /tr "\"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe\" /ua /installsource scheduler" /sc daily /st 02:00 /ru "NT AUTHORITY\SYSTEM"',
                        pid=4208,
                    ),
                    parent_process=ProcessInfo(
                        name="GoogleUpdate.exe",
                        executable=r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
                        command_line=r'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c',
                        pid=3104,
                    ),
                ),
            ),
            "technique_name": "Scheduled Task/Job: Scheduled Task",
            "notes": "Legitimate vendor auto-updater scheduled task created by signed GoogleUpdate.exe binary under Program Files."
        },
        {
            "filename": "benign_T1055.001_appv_virtualization.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1055.001",
                rule_uuid="bng-uuid-1055",
                rule_id="T1055.001",
                rule_name="Process Injection: Dynamic-link Library Injection",
                severity="low",
                risk_score=25,
                timestamp="2026-10-10T08:15:00Z",
                host_name="desktop-thonlnr",
                user_name="victim",
                reason="Application virtualization subsystem hook injection",
                telemetry_source="sysmon",
                event_code="1",
                process_context=ProcessContext(
                    process=ProcessInfo(
                        name="mavinject.exe",
                        executable=r"C:\Windows\System32\mavinject.exe",
                        command_line=r'C:\Windows\system32\mavinject.exe 2480 /INJECTRUNNING "C:\Program Files\Microsoft Office\root\Office16\AppvIsvSubsystems64.dll"',
                        pid=5112,
                    ),
                    parent_process=ProcessInfo(
                        name="AppVClient.exe",
                        executable=r"C:\Program Files\Microsoft Application Virtualization\Client\AppVClient.exe",
                        command_line=r'"C:\Program Files\Microsoft Application Virtualization\Client\AppVClient.exe"',
                        pid=1820,
                    ),
                ),
            ),
            "technique_name": "Process Injection: Dynamic-link Library Injection",
            "notes": "Legitimate Microsoft App-V Client injecting Office subsystem virtualization DLL from Program Files."
        },
        {
            "filename": "benign_T1059.001_sccm_inventory.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1059.001",
                rule_uuid="bng-uuid-1059",
                rule_id="T1059.001",
                rule_name="PowerShell Script Execution",
                severity="low",
                risk_score=20,
                timestamp="2026-10-10T08:20:00Z",
                host_name="desktop-thonlnr",
                user_name=r"NT AUTHORITY\SYSTEM",
                reason="Routine IT hardware asset inventory collection",
                telemetry_source="sysmon",
                event_code="1",
                process_context=ProcessContext(
                    process=ProcessInfo(
                        name="powershell.exe",
                        executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        command_line=r'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Windows\CCM\ScriptLib\HardwareInventory.ps1"',
                        pid=6230,
                    ),
                    parent_process=ProcessInfo(
                        name="CcmExec.exe",
                        executable=r"C:\Windows\CCM\CcmExec.exe",
                        command_line=r"C:\Windows\CCM\CcmExec.exe",
                        pid=1420,
                    ),
                ),
            ),
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "notes": "SCCM agent (CcmExec.exe) executing approved internal hardware inventory script in C:\\Windows\\CCM with non-interactive flags."
        },
        {
            "filename": "benign_T1071.001_1_onedrive_sync.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1071.001-1",
                rule_uuid="bng-uuid-1071-1",
                rule_id="T1071.001",
                rule_name="Suspicious C2 Web Communication",
                severity="low",
                risk_score=20,
                timestamp="2026-10-10T08:25:00Z",
                host_name="desktop-thonlnr",
                user_name="victim",
                reason="Routine enterprise cloud storage sync heartbeat",
                telemetry_source="suricata",
                event_code=None,
                network_context=NetworkContext(
                    source_ip="192.168.1.105",
                    source_port=52410,
                    destination_ip="13.107.136.9",
                    destination_port=443,
                    protocol="tls",
                    direction="egress",
                    user_agent="Microsoft OneDrive Sync 24.086.0428.0001",
                    suricata_signature="ET INFO Microsoft OneDrive Cloud Sync Heartbeat",
                    suricata_category="Corporate Cloud Storage Traffic",
                ),
            ),
            "technique_name": "Application Layer Protocol: Web Protocols (C2)",
            "notes": "Legitimate Microsoft OneDrive cloud storage sync traffic to official Microsoft CDN IP over HTTPS (443)."
        },
        {
            "filename": "benign_T1071.001_2_update_connection.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1071.001-2",
                rule_uuid="bng-uuid-1071-2",
                rule_id="T1071.001",
                rule_name="Outbound Script Network Connection",
                severity="low",
                risk_score=20,
                timestamp="2026-10-10T08:30:00Z",
                host_name="desktop-thonlnr",
                user_name=r"NT AUTHORITY\SYSTEM",
                reason="System Windows Update check connection",
                telemetry_source="sysmon",
                event_code="3",
                process_context=ProcessContext(
                    process=ProcessInfo(
                        name="powershell.exe",
                        executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        command_line=r'powershell.exe -ExecutionPolicy Restricted -Command "Get-WindowsUpdate -AcceptAll"',
                        pid=7120,
                    ),
                    parent_process=ProcessInfo(
                        name="svchost.exe",
                        executable=r"C:\Windows\System32\svchost.exe",
                        command_line=r"C:\Windows\system32\svchost.exe -k netsvcs -p -s wuauserv",
                        pid=1080,
                    ),
                ),
                network_context=NetworkContext(
                    source_ip="192.168.1.105",
                    source_port=49820,
                    destination_ip="20.189.173.1",
                    destination_port=443,
                    protocol="tcp",
                    direction="egress",
                ),
            ),
            "technique_name": "Suspicious Script Outbound Network Connection",
            "notes": "Windows Update service (wuauserv) invoking administrative update cmdlet to official Microsoft Update endpoints."
        },
        {
            "filename": "benign_T1547.001_teams_run_key.json",
            "alert": NormalizedAlert(
                alert_id="BNG-T1547.001",
                rule_uuid="bng-uuid-1547",
                rule_id="T1547.001",
                rule_name="Registry Run Key Persistence",
                severity="low",
                risk_score=20,
                timestamp="2026-10-10T08:35:00Z",
                host_name="desktop-thonlnr",
                user_name="victim",
                reason="User desktop application auto-launch setting registration",
                telemetry_source="sysmon",
                event_code="13",
                process_context=ProcessContext(
                    process=ProcessInfo(
                        name="ms-teams.exe",
                        executable=r"C:\Program Files\WindowsApps\MicrosoftTeams_24102.2212.2829.7425_x64__8wekyb3d8bbwe\ms-teams.exe",
                        command_line=r'"C:\Program Files\WindowsApps\MicrosoftTeams_24102.2212.2829.7425_x64__8wekyb3d8bbwe\ms-teams.exe" /autostart',
                        pid=8412,
                    ),
                    parent_process=ProcessInfo(
                        name="explorer.exe",
                        executable=r"C:\Windows\explorer.exe",
                        command_line=r"C:\Windows\explorer.exe",
                        pid=2040,
                    ),
                ),
                registry_context=RegistryContext(
                    path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams",
                    value_name="com.squirrel.Teams.Teams",
                    data=r"C:\Program Files\WindowsApps\MicrosoftTeams_24102.2212.2829.7425_x64__8wekyb3d8bbwe\ms-teams.exe --autostart",
                    hive="HKCU",
                ),
            ),
            "technique_name": "Registry Run Keys / Startup Folder",
            "notes": "Official Microsoft Teams client registering auto-start under user HKCU Run key during interactive desktop session."
        },
    ]

    records = []
    for item in benign_definitions:
        dst_path = os.path.join(BENIGN_DIR, item["filename"])
        with open(dst_path, "w", encoding="utf-8") as f:
            f.write(item["alert"].model_dump_json(indent=2))
        print(f"[+] Created benign scenario: {dst_path}")

        records.append({
            "alert_id": item["alert"].alert_id,
            "file_path": dst_path.replace("\\", "/"),
            "technique_id": item["alert"].rule_id,
            "technique_name": item["technique_name"],
            "expected_verdict": "Close",
            "scenario_type": "benign",
            "notes": item["notes"]
        })
    return records


def main():
    print("=== Generating Benchmark Dataset ===")
    attack_records = setup_attack_scenarios()
    benign_records = setup_benign_scenarios()

    all_records = attack_records + benign_records
    os.makedirs(os.path.dirname(GROUND_TRUTH_PATH), exist_ok=True)
    with open(GROUND_TRUTH_PATH, "w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"[+] Successfully wrote {len(all_records)} ground-truth records to {GROUND_TRUTH_PATH}!")
    print(f"    - Attack scenarios (Expected Escalate): {len(attack_records)}")
    print(f"    - Benign scenarios (Expected Close):    {len(benign_records)}")


if __name__ == "__main__":
    main()
