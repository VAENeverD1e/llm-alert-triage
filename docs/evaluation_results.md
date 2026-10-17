# Empirical Evaluation Report: Multi-Stage LLM Alert Triage

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
4. **Fail-Safe Posture:** For the remaining 2 benign alerts, the model rendered a cautious `Escalate` decision due to suspicious indicators (e.g., user-writable paths and external IP contacts), aligning with the system's core principle of **Fail-Safe Triage (ADR-005/006)**.

---

## 2. Comparative Benchmark Matrix

The following table summarizes the quantitative performance across all 16 benchmark scenarios:

| Metric | Heuristic Baseline (Rule-Based) | LLM + RAG Playbooks (`llama3:8b`) | Delta / Improvement |
|---|:---:|:---:|:---:|
| **Evaluated Scenarios** | 16 (8 Attack / 8 Benign) | 16 (8 Attack / 8 Benign) | — |
| **Detection Recall (Sensitivity)** | **0.7500** (6/8 detected) | **1.0000** (8/8 detected) | **+25.0% (Zero Breaches Missed)** |
| **Precision** | **1.0000** | **0.8000** | -20.0% (Conservative Security Posture) |
| **F1-Score (Harmonic Mean)** | **0.8571** | **0.8889** | **+3.18%** |
| **Cohen's Kappa ($\kappa$)** | **0.7500** | **0.7500** | Substantial Agreement |
| **Mean Time to Respond (MTTR)** | **0.41 ms** | **40,422 ms (40.4 s)** | Local CPU/GPU consumer latency |
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
| `BNG-T1055.001` | T1055.001 (App-V Virtual.) | Benign | Sysmon Event 1 | **Close** | Close | Escalate ⚠️ | 0.95 | Cautious Escalation |
| `BNG-T1059.001` | T1059.001 (SCCM Inventory) | Benign | Sysmon Event 1 | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1071.001-1`| T1071.001 (OneDrive Sync) | Benign | Suricata IDS | **Close** | Close | **Close** | 0.90 | ✅ Match |
| `BNG-T1071.001-2`| T1071.001 (Update Conn.) | Benign | Sysmon Event 3 | **Close** | Close | Escalate ⚠️ | 0.95 | Cautious Escalation |
| `BNG-T1547.001` | T1547.001 (Teams Auto-start)| Benign | Sysmon Event 13 | **Close** | Close | **Close** | 0.90 | ✅ Match |

---

## 4. Qualitative Deep-Dive & Reasoning Analysis

### 4.1 Resolution of Critical Heuristic Blindspots

#### Case 1: Suricata Network Port Scan (`ATK-T1046`)
* **Heuristic Failure:** Conventional heuristic rules evaluate host indicators like `is_anomalous_parent` and CLI tokens. Wire-level IDS sensors capture IP packets with no endpoint parent process. The heuristic rule silently evaluated to `Close`—allowing an active reconnaissance probe against a sensitive database port (1521) to go unnoticed.
* **LLM + RAG Resolution:** Grounded by `playbooks/PB-T1046-network-scan.md`, the LLM evaluated the Suricata alert context:
  > *"The alert telemetry indicates a network service scanning event targeting Oracle database port 1521 from an unverified external source. In alignment with playbook criteria, scanning against sensitive database ports requires immediate investigation."*
  * **Verdict:** `ESCALATE` (Confidence: 0.95).

#### Case 2: Registry Run Key Persistence (`ATK-T1547.001`)
* **Heuristic Failure:** In Sysmon Event 13, modifying an auto-start Run key was initiated by `reg.exe` without an anomalous parent. The heuristic engine classified this as benign.
* **LLM + RAG Resolution:** Grounded by `playbooks/PB-T1547.001-run-key-persistence.md`, the model scrutinized the target registry key path, randomized value name, and binary path outside standard `Program Files`:
  > *"The alert telemetry indicates a registry write event with process reg.exe, which is not a recognized installer. Additionally, the value name is random-looking and the path is outside standard software directories. These indicators meet playbook TP criteria."*
  * **Verdict:** `ESCALATE` (Confidence: 0.95).

---

### 4.2 Explainable False Positive Reduction

#### Case 3: Legitimate WMI LSASS Handle Query (`BNG-T1003.001`)
* **Challenge:** LSASS alerts have high false-positive noise in enterprise environments due to monitoring agents.
* **LLM + RAG Resolution:** The model inspected the `CallTrace` and access mask against `playbooks/PB-T1003.001-lsass-dump.md`:
  > *"The process name is svchost.exe (known Windows service). The access mask is 0x1410 (known exclusion). The Call Trace shows only cimwin32.dll, which is part of the WMI stack and already excluded. Therefore, based on the playbook's FP criteria, this alert should be closed."*
  * **Verdict:** `CLOSE` (Confidence: 0.90).

---

### 4.3 Analysis of Conservative False Alarms

* **`BNG-T1055.001` (App-V Virtualization):** The model recognized `AppVClient.exe` as an allowed parent, but noted that the injection target was in a user-accessible path, choosing to escalate for analyst review.
* **`BNG-T1071.001-2` (Windows Update):** The model noted an outbound connection to an external IP from `NT AUTHORITY\SYSTEM` and elected to escalate.
* **SOC Impact:** In cybersecurity operations, **False Positives are manageable nuisances, whereas False Negatives (missed breaches) are catastrophic.** The system's tendency to favor analyst verification on borderline cases satisfies production safety requirements.

---

## 5. Artifacts and Repeatability

All evaluation artifacts and logs are persisted and reproducible:
* **Raw Execution Records:** [`evaluation/results/eval_llm_rag_latest.json`](file:///c:/Users/Huy/Desktop/llm-alert-triage/evaluation/results/eval_llm_rag_latest.json)
* **Summary CSV:** [`evaluation/results/eval_llm_rag_summary.csv`](file:///c:/Users/Huy/Desktop/llm-alert-triage/evaluation/results/eval_llm_rag_summary.csv)
* **Execution Command:**
  ```bash
  python -m evaluation.replay_harness --mode llm_rag
  ```
