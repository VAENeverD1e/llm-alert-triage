# LLM-Based Security Alert Triage System

An automated two-stage LLM agent system designed to triage SIEM/Elastic security alerts, gather contextual telemetry, evaluate alert severity, and issue triage decisions (Escalate / Close) with explainable reasoning and confidence metrics.

---

## 🏗 System Architecture

```text
+-------------------+      +----------------------+      +------------------+      +-------------------+
|  SIEM / Elastic   | ---> |  Fact-Finding Agent  | ---> |  Verdict Agent   | ---> | Discord / Alerting|
|  Security Alerts  |      | (Event Aggregation)  |      | (Escalate/Close) |      |   Notifications   |
+-------------------+      +----------------------+      +------------------+      +-------------------+
                                  ^                             ^
                                  |                             |
                          (Raw Event Logs)              (RAG / Playbooks)
```

### Key Components

- **Detection**: Ingests SIEM rules (`config/rules_tight.ndjson`, `config/rules_loose.ndjson`).
- **Fact-Finding Agent** (`agent/fact_finding/`): Aggregates raw process, network, and user logs around an alert without making diagnostic judgments.
- **Verdict Agent** (`agent/verdict/`): Analyzes aggregated facts grounded by security playbooks (`integrations/playbook_retriever.py`) to render an `Escalate` or `Close` verdict with detailed reasoning and confidence scores.
- **Orchestrator** (`agent/orchestrator.py`): Coordinates the two-stage execution pipeline.
- **Integrations**: Interfaces with Elastic (`elastic_client.py`), local Ollama models (`ollama_client.py`), and Playbook retrieval.
- **Notification**: Delivers structured triage results to Discord (`notification/discord_forwarder.py`).
- **Evaluation**: Replay harness (`evaluation/replay_harness.py`), metrics calculator (`evaluation/metrics.py`), and prompt injection tests (`evaluation/prompt_injection/`).

---

## 📁 Repository Structure

```text
llm-alert-triage/
├── README.md                           # Main project overview and setup guide
├── docs/                               # Architectural diagrams, decision logs, and proposals
│   ├── proposal_condensed.docx         # Thesis / research proposal reference
│   ├── architecture.png                # High-level architecture diagram
│   └── decisions.md                    # Scope-cut log & architectural decision record (ADR)
├── config/                             # Rule definitions & agent parameters
│   ├── rules_tight.ndjson              # Production-tier SIEM rules (with exclusions)
│   ├── rules_loose.ndjson              # Unfiltered SIEM rules (for experimentation)
│   └── agent_config.yaml               # Model configuration, token limits, and tool permissions
├── data/                               # Dataset & replay scenarios
│   ├── attack_scenarios/               # Scripted replay defs for 7 MITRE ATT&CK T-IDs
│   ├── benign_scenarios/               # Scripted benign-noise generators
│   ├── optc_subset/                    # DARPA OpTC sample dataset & loader
│   └── ground_truth.jsonl              # Labeled alert evaluation dataset (alert_id -> Escalate/Close)
├── agent/                              # Core LLM Triage Logic
│   ├── fact_finding/                   # Aggregates surrounding event logs without judgment
│   ├── verdict/                        # Decision-making module (Escalate/Close + reasoning)
│   ├── schemas/                        # Pydantic / JSON schemas for agent inputs and outputs
│   └── orchestrator.py                 # Pipeline manager executing stage 1 & stage 2
├── integrations/                       # External Service Integrations
│   ├── elastic_client.py               # Ingests alerts and queries Elasticsearch/Kibana
│   ├── playbook_retriever.py           # RAG retrieval module for security response playbooks
│   └── ollama_client.py                # Interface for local LLM inference (e.g., Llama 3/Mistral)
├── notification/                       # Alerting & Webhooks
│   └── discord_forwarder.py            # Formats and sends triage results to Discord channels
├── evaluation/                         # Benchmarking & Security Testing
│   ├── replay_harness.py               # Automated execution harness for scenario testing
│   ├── metrics.py                      # Metrics (Precision, Recall, F1, MTTR, Cohen's kappa)
│   ├── prompt_injection/               # Adversarial alert payload testing & safety checks
│   └── results/                        # Evaluation run outputs (CSV/JSON)
├── tests/                              # Unit & Integration Tests
│   ├── test_agent_schema.py            # Validates JSON schemas for agent communications
│   └── test_orchestrator.py            # End-to-end pipeline execution tests
└── scripts/                            # Operational Scripts
    └── setup_ollama.sh                 # Environment setup and model pull script for Ollama
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai/) installed locally (or access to an OpenAI-compatible API)
- Elasticsearch / Kibana instance (optional for local mock testing)

### Setup

1. **Clone & Setup Environment**

   ```bash
   git clone <repo-url>
   cd llm-alert-triage
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt  # (Create environment dependencies)
   ```

2. **Pull Ollama Models**

   ```bash
   bash scripts/setup_ollama.sh
   ```

3. **Run Pipeline Tests**

   ```bash
   pytest tests/
   ```

---

## 📊 Evaluation & Metrics

Run the evaluation harness to compute performance metrics across benign and attack scenarios:

```bash
python -m evaluation.replay_harness
python -m evaluation.metrics
```
