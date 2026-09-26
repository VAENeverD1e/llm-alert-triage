# Architectural Decision Records & Scope Cuts

This document logs key architectural choices, trade-offs, descoped items, and detection telemetry resolutions during the development of the LLM Alert Triage system.

---

## 📑 Architectural Decision & Scope-Cut Log

| ID | Feature / Component | Initial Status | Descoped / Modified | Rationale |
|---|---|---|---|---|
| ADR-001 | Single-Agent Triage | Proposed | Descoped | A single LLM prompt trying to perform telemetry gathering AND verdict assessment hallucinated event evidence. Split into Stage 1 (Fact-Finding) and Stage 2 (Verdict). |
| ADR-002 | Autonomous Remediation | Considered | Descoped | Direct host isolation or account disabling via LLM was deemed high risk for production. System focuses exclusively on triage recommendation (`Escalate` vs `Close`). |
| ADR-003 | Full Graph DB Context | Considered | Simplified | Querying Neo4j for full process graph introduced latency. Replaced with windowed Elasticsearch event aggregation around alert timestamp ($\pm 5$ minutes). |
| ADR-004 | Fine-Tuning Local Models | Considered | Replaced by RAG | RAG with response playbooks yields better explainability and easier updates than static weights fine-tuning. |
| ADR-005 | Schema Architecture & `SecurityAlert` Replacement | Proposed | Modified / Adopted | Replaced flat `SecurityAlert` (with untyped `raw_event: Dict[str, Any]`) with `NormalizedAlert` using an Envelope + 3 Optional Context Blocks (`ProcessContext`, `RegistryContext`, `NetworkContext`). |
| ADR-006 | Three-Tier Telemetry Field Taxonomy | Proposed | Adopted | Established strict boundaries across Envelope, Technique-Specific, and Enrichment-Only fields, defining exact query obligations for the Fact-Finding Agent. |
| ADR-007 | SIEM Detection Rule-Drift & Telemetry Ingestion | Discovered | Resolved | Resolved discrepancies between `.ndjson` rule definitions and live Kibana documents (`SourceImage` vs `process.name`, missing `user.name` in Event 10, subtechnique truncation, Suricata host blindspot). |

---

## 🏛 Architecture Principles

1. **Strict Stage Separation**: Stage 1 Fact-Finding Agent produces unbiased telemetry summaries without diagnostic judgment.
2. **Schema Enforcement**: All inter-agent and output communications must conform to Pydantic JSON schemas. Untyped dictionaries (`Dict[str, Any]`) are prohibited across pipeline boundaries.
3. **Fail-Safe Triage**: Any pipeline error or output schema parsing failure defaults to `Escalate` with a high severity alert to SOC analysts.
4. **Adversarial Resilience**: Alert input fields must be sanitized before prompt insertion to prevent prompt injection attacks.

---

## 🔬 Detailed Decision Records

### ADR-005: Schema Modularization & Replacement of `SecurityAlert`

* **Context:**
  The initial data model ([`agent/schemas/triage_schema.py`](file:///c:/Users/Huy/Desktop/llm-alert-triage/agent/schemas/triage_schema.py)) defined a flat `SecurityAlert` with non-optional `host_name: str`, `user_name: str`, and an untyped `raw_event: Dict[str, Any]`. Auditing the 8 live SIEM samples in [`docs/samples/`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/) revealed that raw alerts split into two non-overlapping telemetry families:
  1. **Host-origin (Sysmon):** Rich in process trees, hashes, registry changes, and memory access masks.
  2. **Network-origin (Suricata IDS):** Pure packet flow observations (`source.ip`, `destination.ip`, `user_agent`, signature) with **zero process or host identity**.
* **Decision:**
  Adopt [`NormalizedAlert`](file:///c:/Users/Huy/Desktop/llm-alert-triage/agent/schemas/triage_schema.py) as the canonical input schema, replacing `SecurityAlert` outright:
  * **Common Envelope:** Holds metadata universal to all alerts (`alert_id`, `rule_uuid`, `rule_id`, `rule_name`, `severity`, `risk_score`, `timestamp`, `host_name`, `user_name`, `telemetry_source`, `event_code`, `reason`).
  * **Modular Context Blocks:** Only populated when relevant:
    * `process_context`: Handles Process Creation (Event 1), Network Connections (Event 3), LSASS Memory Access (Event 10), and Registry edits (Event 13).
    * `registry_context`: Handles Registry Run key additions/modifications (Event 13).
    * `network_context`: Handles Sysmon network sockets (Event 3) and Suricata alerts.
  * **ETL Ingestion Engine (`from_raw_alert`):** Traverses hybrid Kibana signals (which mix flat dotted keys like `kibana.alert.uuid` with nested ECS dicts like `{"event": {"code": 1}}`) and safely normalizes them without runtime crashes.
  * **Backwards Compatibility:** Maintained `SecurityAlert = NormalizedAlert` alias so existing unit tests and orchestrator components continue to function seamlessly.

---

### ADR-006: Three-Tier Telemetry Field Taxonomy (Enrichment Boundary)

* **Context:**
  A major failure mode in LLM triage systems is confusing data *already present* in the trigger alert with data that *must be enriched* from surrounding logs. Trying to extract non-existent fields causes prompt hallucinations.
* **Decision:**
  Every telemetry attribute across the triage lifecycle is formally partitioned into three operational tiers (detailed in [`docs/alert-schema-audit.md`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/alert-schema-audit.md)):
  1. **Envelope (Universal Header):** Root fields present in all alerts. Directly parsed by `from_raw_alert`.
  2. **Technique-Specific (Intra-Alert Evidence):** High-signal fields present inside the triggering alert document for specific event codes (e.g., `winlog.event_data.TargetImage` for LSASS; `registry.data.strings` for Run Keys).
  3. **Enrichment-Only (Active Fact-Finding Requirements):** Essential forensic context **absent from the triggering alert** that the Stage 1 Fact-Finding Agent must actively query:
     * *Parent Process Telemetry:* Sysmon Events 3, 10, and 13 do not capture parent processes. The agent must query Event 1 process creation events within a $\pm 5$-minute window using `process.pid` or `process.entity_id`.
     * *Host Identity for Network IDS:* Suricata alerts contain IP addresses but no hostname. The agent must resolve IP $\to$ Host via DHCP/Asset logs.
     * *Process Command Lines & Hashes for Non-Creation Events:* Events 3, 10, and 13 omit CLI tokens and hashes, requiring temporal correlation with process spawn events.
     * *IP Reputation & User Privileges:* Outbound external IPs and user accounts must be checked against threat intel APIs and Active Directory groups.

---

### ADR-007: SIEM Detection Rule-Drift & Telemetry Ingestion Resolutions

* **Context:**
  Cross-referencing production SIEM rule definitions ([`config/rules_tight.ndjson`](file:///c:/Users/Huy/Desktop/llm-alert-triage/config/rules_tight.ndjson)) against live alert documents ([`docs/samples/`](file:///c:/Users/Huy/Desktop/llm-alert-triage/docs/samples/)) uncovered four silent detection bugs:
  1. **LSASS Process Name vs. `SourceImage` (`T1003.001`):** `rules_tight.ndjson` specified `"exclusions": ["process.name: Taskmgr.exe"]`, but raw Windows Event 10 queries check `winlog.event_data.SourceImage: *taskmgr.exe`. Normalization bridges both layers by mapping `SourceImage` to `process.executable` and `process.name`.
  2. **Missing `user.name` on LSASS Alerts (`T1003.001`):** In live Event 10 logs, ECS `user` only contains `{"id": "S-1-5-18"}`. The actual human username resides in `winlog.event_data.SourceUser: "DESKTOP-THONLNR\victim"`. `from_raw_alert()` implements an explicit fallback to ensure `user_name` is never lost.
  3. **Subtechnique Truncation (`T1003.001` & `T1547.001`):** In several Kibana alert exports, the threat framework array defined technique IDs (`T1003`, `T1547`) with empty `subtechnique: []` arrays, even though rule names and descriptions explicitly referenced `T1003.001` and `T1547.001`. A regex fallback `(T\d{4}\.\d{3})` was integrated into `from_raw_alert()` to recover subtechniques for accurate playbook retrieval.
  4. **Suricata Host Blindspot:** Suricata alerts omit `host` entirely. The schema makes `host_name: Optional[str]` to prevent validation crashes and flags host resolution as an active enrichment query.
