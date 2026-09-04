# Architectural Decision Records & Scope Cuts

This document logs key architectural choices, trade-offs, and descoped items during the development of the LLM Alert Triage system.

---

## 📑 Scope-Cut Log

| ID | Feature / Component | Initial Status | Descoped / Modified | Rationale |
|---|---|---|---|---|
| ADR-001 | Single-Agent Triage | Proposed | Descoped | A single LLM prompt trying to perform telemetry gathering AND verdict assessment hallucinated event evidence. Split into Stage 1 (Fact-Finding) and Stage 2 (Verdict). |
| ADR-002 | Autonomous Remediation | Considered | Descoped | Direct host isolation or account disabling via LLM was deemed high risk for production. System focuses exclusively on triage recommendation (`Escalate` vs `Close`). |
| ADR-003 | Full Graph DB Context | Considered | Simplified | Querying Neo4j for full process graph introduced latency. Replaced with windowed Elasticsearch event aggregation around alert timestamp ($\pm 5$ minutes). |
| ADR-004 | Fine-Tuning Local Models | Considered | Replaced by RAG | RAG with response playbooks yields better explainability and easier updates than static weights fine-tuning. |

---

## 🏛 Architecture Principles

1. **Strict Stage Separation**: Stage 1 Fact-Finding Agent produces unbiased telemetry summaries without diagnostic judgment.
2. **Schema Enforcement**: All inter-agent and output communications must conform to Pydantic JSON schemas.
3. **Fail-Safe Triage**: Any pipeline error or output schema parsing failure defaults to `Escalate` with a high severity alert to SOC analysts.
4. **Adversarial Resilience**: Alert input fields must be sanitized before prompt insertion to prevent prompt injection attacks.
