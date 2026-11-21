# Empirical Evaluation Report: Multi-Stage LLM Alert Triage

> **STATUS: INVALIDATED — DO NOT USE THE NUMBERS BELOW.** The 2026-10-17 run predates
> severity removal, sanitization, placeholder filtering, fair benchmark normalization,
> and the confidence policy. It also did not establish Elastic enrichment coverage.
> Re-run the benchmark with the updated harness before citing any metric. The harness
> now records `label_leakage_sanitized` and `enrichment_configured` in its JSON output.

> **2026-11 update (evaluation integrity fixes).** The harness now (a) strips Kibana workflow status,
> `kibana.alert.reason`, the `fields` block, host/user names and real IPs from raw alerts, (b) no longer
> lets severity reach the heuristic or Stage 1 evidence unless `--include-severity` is set, (c) reports
> `Unknown` verdicts (`coverage`, `recall_strict`) and LLM/pipeline fallbacks (`verdict_source`), and
> (d) flags 3 benign samples (`BNG-T1003.001`, `BNG-T1055.001`, `BNG-T1071.001-2`) with
> `rule_would_fire: false` because the real Kibana rules exclude them; `metrics_realistic_only` omits them.
> With these fixes the heuristic baseline (no severity) scores P=1.00, R=0.375, F1=0.5455 on the 16 alerts:
> the earlier heuristic recall of 0.75 depended on the severity shortcut. LLM numbers must be re-run.

**Timestamp:** 2026-10-17  
**Evaluation Target:** Two-Stage LLM Triage Architecture vs. Rule-Based Heuristic Baseline  
**Model Under Test:** Local `llama3:8b` via Ollama (`http://localhost:11434`)  
**Context Grounding:** 7 MITRE ATT&CK RAG Incident Response Playbooks (`playbooks/PB-*.md`)  
**Benchmark Dataset:** 16 Standardized Scenarios (8 Attack True Positives + 8 Benign False Positives)  

---

## 1. Executive Summary

This evaluation measures the empirical effectiveness of the **Two-Stage LLM Alert Triage System** against a standard **Rule-Based Heuristic Baseline**. The test evaluates whether an LLM acting as an automated SOC Analyst, grounded by MITRE ATT&CK Incident Response Playbooks, can overcome the structural blindspots of conventional SIEM rules without introducing unacceptable latency or hallucinations.

### Key Findings
1. **Zero Missed Breaches (100% Recall):** The LLM + RAG pipeline achieved a **Recall of 1.0000** (8/8 attacks detected), successfully detecting attacks that bypassed the rule-based baseline.
2. **Elimination of Rule Blindspots:** The heuristic baseline missed 25% of true attacks (**Recall: 0.7500**) because conventional rules depend heavily on anomalous parent-process chains, which are absent in network IDS alerts (`T1046`) and direct registry modifications (`T1547.001`). The LLM + RAG pipeline correctly escalated both.
3. **High-Fidelity False Positive Filtering:** The LLM + RAG pipeline successfully filtered **75% of benign enterprise noise** (6/8 alerts closed), accurately quoting the exact exclusion criteria (WMI DLL stacks, authorized subnets, signed vendor binaries) specified in the incident playbooks.
4. **Two False Positives Were LLM Hallucinations:** The 2 benign alerts the model escalated were driven by fabricated evidence (an invented threat-intelligence hit and a Program Files path misread as user-writable), not by a cautious posture. See Section 4.3.

---

## 2. Comparative Benchmark Matrix

The following table summarizes the quantitative performance across all 16 benchmark scenarios:

| Metric | Heuristic Baseline (Rule-Based) | LLM + RAG Playbooks (`llama3:8b`) | Delta / Improvement |
|---|:---:|:---:|:---:|
| **Evaluated Scenarios** | 16 (8 Attack / 8 Benign) | 16 (8 Attack / 8 Benign) | — |
| **Detection Recall (Sensitivity)** | **0.7500** (6/8 detected) | **1.0000** (8/8 detected) | **+25.0% (Zero Breaches Missed)** |
| **Precision** | **1.0000** | **0.8000** | -20.0% (2 hallucination-driven FPs, see 4.3) |
| **F1-Score (Harmonic Mean)** | **0.8571** | **0.8889** | **+3.18%** |
| **Cohen's Kappa ($\kappa$)** | **0.7500** | **0.7500** | Substantial Agreement |
| **Mean Time to Respond (MTTR)** | **HISTORICAL — INVALID** | **HISTORICAL — INVALID** | Re-run required; prior values must not be cited |
| **Missed Attacks (False Negatives)** | **2** (`T1046`, `T1547.001`) | **0** | **100% Attack Coverage** |
| **Benign Noise Filtered (True Negatives)**| 8 / 8 (100%) | 6 / 8 (75%) | Safe FP Reduction |

---

## 3. Per-Scenario Evaluation Breakdown

| Alert ID | MITRE Technique | Scenario Type | Telemetry Source | Expected | Heuristic Verdict | LLM + RAG Verdict | LLM Conf. | Status |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|
| `ATK-T1003.001` | T1003.001 (LSASS Dump) | Attack | Sysmon Event 10 | **Escalate** | Escalate | **Escalate** | 0.95 | ✅ Match |
| `ATK-T1046` | T1046 (Port Scan) | Attack | Suricata IDS | **Escalate** | Close ❌ | **Escalate** | 0.95 | ✅ **Fixed by LLM** |
| `ATK-T1053.005` | T1053.005 (Scheduled Task) | Attack | Sysmon Event 1 | **Escalate** | Escalate | **Escalate** | 0.95 | ✅ Match |
| `ATK-T1055.001` | T1055.001 (DLL Injection) | Attack | Sysmon Event 1 | **Escalate** | Escalate | **Escalate** | 0.95 | ✅ Match |
| `ATK-T1059.001` | T1059.001 (PowerShell) | Attack | Sysmon Event 1 | **Escalate** | Escalate | **Escalate** | 0.95 | ✅ Match |
| `ATK-T1071.001-1`| T1071.001 (C2 Beacon) | Attack | Suricata IDS | **Escalate** | Escalate | **Escalate** | 0.95 | ✅ Match |
| `ATK-T1071.001-2`| T1071.001 (Script Socket) | Attack | Sysmon Event 3 | **Escalate** | Escalate | **Escalate** | 0.95 | ✅ Match |
| `ATK-T1547.001` | T1547.001 (Registry Run Key)| Attack | Sysmon Event 13 | **Escalate** | Close ❌ | **Escalate** | 0.95 | ✅ **Fixed by LLM** |
| `BNG-T1003.001` | T1003.001 (LSASS WMI Query)| Benign | Sysmon Event 10 | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1046` | T1046 (Nessus Scanner) | Benign | Suricata IDS | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1053.005` | T1053.005 (Updater Task) | Benign | Sysmon Event 1 | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1055.001` | T1055.001 (App-V Virtual.) | Benign | Sysmon Event 1 | **Close** | Close | Historical result — invalid | — | Re-run required |
| `BNG-T1059.001` | T1059.001 (SCCM Inventory) | Benign | Sysmon Event 1 | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1071.001-1`| T1071.001 (OneDrive Sync) | Benign | Suricata IDS | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1071.001-2`| T1071.001 (Update Conn.) | Benign | Sysmon Event 3 | **Close** | Close | Historical result — invalid | — | Re-run required |
| `BNG-T1547.001` | T1547.001 (Teams Auto-start)| Benign | Sysmon Event 13 | **Close** | Close | **Close** | 0.90 | ✅ Match |

---

## 4. Qualitative Deep-Dive & Reasoning Analysis

### 4.1 Resolution of Critical Heuristic Blindspots

#### Case 1: Suricata Network Port Scan (`ATK-T1046`)
* **Heuristic Failure:** Conventional heuristic rules evaluate host indicators like `is_anomalous_parent` and CLI tokens. Wire-level IDS sensors capture IP packets with no endpoint parent process. The heuristic rule silently evaluated to `Close`—allowing an active reconnaissance probe against a sensitive database port (1521) to go unnoticed.
* **LLM + RAG Resolution:** Grounded by `playbooks/PB-T1046-network-scan.md`, the LLM evaluated the Suricata alert context:
  > *"The alert is triggered on a sensitive port (1521) and the source IP is not recognized as an authorized scanner. Additionally, the scan occurs outside business hours, which is a strong indicator of potential malicious activity. The playbook's TP vs FP criteria are met, and therefore, this alert should be escalated."*
  * **Verdict:** `ESCALATE` (Confidence: 0.95).
  * *Critical Observation:* Note that the model correctly escalated based on sensitive port 1521, but hallucinated that the scan occurred "outside business hours" (as no business hour metadata was provided).

#### Case 2: Registry Run Key Persistence (`ATK-T1547.001`)
* **Heuristic Failure:** In Sysmon Event 13, modifying an auto-start Run key was initiated by `reg.exe` without an anomalous parent. The heuristic engine classified this as benign.
* **LLM + RAG Resolution:** Grounded by `playbooks/PB-T1547.001-run-key-persistence.md`, the model scrutinized the target registry key path, randomized value name, and binary path outside standard `Program Files`:
  > *"The alert telemetry indicates a registry write event with process reg.exe, which is not a recognized installer process. Additionally, the value name is random-looking, and the executable path is not under a recognized software directory. These indicators align with the playbook's TP criteria, suggesting a potential true positive."*
  * **Verdict:** `ESCALATE` (Confidence: 0.95).

---

### 4.2 Explainable False Positive Reduction

#### Case 3: Legitimate WMI LSASS Handle Query (`BNG-T1003.001`)
* **Challenge:** LSASS alerts have high false-positive noise in enterprise environments due to monitoring agents.
* **LLM + RAG Resolution:** The model inspected the `CallTrace` and access mask against `playbooks/PB-T1003.001-lsass-dump.md`:
  > *"The alert telemetry and investigation findings do not match any of the True Positive escalation criteria. The process name is svchost.exe, which is a known Windows service process. The access mask is 0x1410, which is also a known exclusion. The Call Trace shows only cimwin32.dll, which is part of the WMI stack and already excluded. Therefore, based on the playbook's FP criteria, this alert should be closed."*
  * **Verdict:** `CLOSE` (Confidence: 0.90).

---

### 4.3 Critical Analysis of False Positives & Model Hallucinations

In the benign dataset, 2 out of 8 alerts were incorrectly escalated by the model. Rather than framing these purely as "cautious escalation", forensic auditing of the raw model reasoning reveals specific **LLM hallucination patterns** that represent operational areas for improvement:

1. **`BNG-T1055.001` (App-V Virtualization): Directory Hallucination**
   * *Actual Telemetry:* The injected DLL is located at `C:\Program Files\Microsoft Office\root\Office16\AppvIsvSubsystems64.dll` (a system-protected directory).
   * *Model Reasoning:* *"However, the injected DLL path is in a user-writable directory, which is a TP criterion."*
   * *Analysis:* The LLM hallucinated the filesystem permission model, falsely categorizing a standard `Program Files` directory as user-writable.

2. **`BNG-T1071.001-2` (Windows Update Check): Threat Intel & Account Hallucination**
   * *Actual Telemetry:* Host initiated an outbound HTTPS connection to `20.189.173.1:443` (official Microsoft Windows Update CDN) under `NT AUTHORITY\SYSTEM`. Threat intelligence lookups are disabled (`allow_network_lookups: false`).
   * *Model Reasoning:* *"an outbound connection from the host 'desktop-thonlnr' to an external IP '20.189.173.1:443', which is flagged in threat intelligence. Additionally, the user is NT AUTHORITY/system, which is not a typical user for a Windows Update check."*
   * *Analysis:* The model invented external threat intelligence ("flagged in threat intelligence") and demonstrated flawed domain knowledge by claiming `NT AUTHORITY\SYSTEM` is atypical for Windows Update (in reality, `SYSTEM` is the standard security context for `wuauserv`).

* **Remediation & Lessons Learned:**
  * Strict schema ground truth constraints must prevent the model from assuming external facts not present in telemetry.
  * Adding an explicit verification step (e.g. checking path against trusted directory prefixes via code rather than LLM intuition) eliminates such classification errors.

---

## 5. Artifacts and Repeatability

All evaluation artifacts and logs are persisted and reproducible:
* **Raw Execution Records:** [`evaluation/results/eval_llm_rag_latest.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/evaluation/results/eval_llm_rag_latest.json)
* **Summary CSV:** [`evaluation/results/eval_llm_rag_summary.csv`](file:///c:/Users/Huy/Desktop/llm-alert-triage/evaluation/results/eval_llm_rag_summary.csv)
* **Execution Command:**
  ```bash
  python -m evaluation.replay_harness --mode llm_rag
  ```
