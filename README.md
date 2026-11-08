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
├── api/                                # FastAPI Webhook Ingestion & Alert Gateway
│   ├── main.py                         # Application entrypoint with sequential FIFO worker
│   ├── service.py                      # Triage singleton service manager
│   ├── schemas.py                      # Webhook request/response Pydantic models
│   └── config.py                       # API settings & authentication configuration
├── playbooks/                          # Grounded RAG Incident Response Playbooks
│   └── PB-*.md                         # MITRE ATT&CK response guides (TP vs FP criteria)
├── soc_portal/                         # SOC Analyst Web Dashboard & Visualizer
│   ├── backend/                        # FastAPI dashboard endpoints
│   └── frontend/                       # Vite/React SOC operations interface
├── docs/                               # Architectural diagrams, decision logs, and proposals
│   ├── alert-schema-audit.md           # Schema audit & SIEM telemetry mapping
│   ├── evaluation_results.md           # Empirical benchmark evaluation report
│   ├── project_limitations_and_analysis.md # In-depth project critique & technical roadmap
│   └── decisions.md                    # Scope-cut log & architectural decision record (ADR)
├── config/                             # Rule definitions & agent parameters
│   ├── rules_tight.ndjson              # Production-tier SIEM rules (with exclusions)
│   ├── rules_loose.ndjson              # Unfiltered SIEM rules (for experimentation)
│   └── agent_config.yaml               # Model configuration, token limits, and tool permissions
├── data/                               # Dataset & replay scenarios
│   ├── attack_scenarios/               # Scripted replay defs for MITRE ATT&CK T-IDs
│   ├── benign_scenarios/               # Scripted benign-noise enterprise scenarios
│   └── ground_truth.jsonl              # 16 Labeled alert evaluation benchmark (8 ATK / 8 BNG)
├── agent/                              # Core Two-Stage LLM Triage Logic
│   ├── fact_finding/                   # Stage 1: Aggregates surrounding event logs without bias
│   ├── verdict/                        # Stage 2: RAG playbook reasoning & Escalate/Close decision
│   ├── security/                       # Adversarial PromptGuard delimiter & injection defense
│   ├── schemas/                        # Pydantic schemas (NormalizedAlert, Context Blocks)
│   └── orchestrator.py                 # Pipeline manager coordinating Stages 1 & 2
├── integrations/                       # External Service Integrations
│   ├── elastic_client.py               # Ingests alerts and queries Elasticsearch/Kibana
│   ├── playbook_retriever.py           # RAG retrieval module for security response playbooks
│   └── ollama_client.py                # Interface for local LLM inference (e.g., Llama 3)
├── notification/                       # Alerting & Webhooks
│   └── discord_forwarder.py            # Formats and sends color-coded alerts to Discord channels
├── evaluation/                         # Benchmarking & Security Testing
│   ├── replay_harness.py               # Automated execution harness for scenario testing
│   ├── metrics.py                      # Metrics (Precision, Recall, F1, Latency, Cohen's kappa)
│   ├── prompt_injection/               # Adversarial alert payload testing & safety suite
│   └── results/                        # Evaluation run outputs (CSV/JSON)
├── tests/                              # Unit & Integration Tests (100% pytest suite)
└── scripts/                            # Operational Scripts
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

---

## 🌐 Running the REST API & Webhook Service

The gateway exposes a production-grade FastAPI service receiving Kibana/Elasticsearch alert webhooks, executing sequential two-stage triage, and dispatching Rich Embed notifications to Discord.

### 1. Configuration (`.env`)

Copy `.env.example` to `.env` and set secret parameters:

```bash
cp .env.example .env
```

Key environment variables:
* `WEBHOOK_SECRET`: Secret token for webhook authentication (`X-Webhook-Secret` or `Authorization: Bearer <secret>`).
* `DISCORD_WEBHOOK_URL`: Target Discord channel webhook URL.
* `ELASTIC_URL`: Elasticsearch host URL (e.g. `http://192.168.31.130:9200`).
* `OLLAMA_HOST`: Local Ollama service endpoint (default: `http://localhost:11434`).

### 2. Start the Server

```bash
# Using launcher script
python scripts/run_server.py --host 0.0.0.0 --port 8000 --reload

# Or directly with Uvicorn
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

* **Interactive OpenAPI Docs:** `http://localhost:8000/docs`
* **Live Health Check:** `http://localhost:8000/health`
* **Audit Results Feed:** `http://localhost:8000/results`

### 3. Curl Examples

#### Ingest Webhook Alert (Immediate HTTP 202 Accepted)
```bash
curl -X POST "http://localhost:8000/webhook/alert" \
     -H "Content-Type: application/json" \
     -H "X-Webhook-Secret: your_secret_here" \
     -d '{
       "alert_id": "ATK-DEMO-001",
       "rule_id": "T1059.001",
       "rule_name": "PowerShell Encoded Script Execution",
       "severity": "high",
       "host_name": "FINANCE-PC01",
       "user_name": "jdoe",
       "process_context": {
         "process": {
           "name": "powershell.exe",
           "command_line": "powershell.exe -Enc SQBFAFgA...",
           "pid": 5824
         }
       }
     }'
```

#### Synchronous Test Triage
```bash
curl -X POST "http://localhost:8000/triage/test" \
     -H "Content-Type: application/json" \
     -d '{
       "alert_id": "TEST-001",
       "rule_id": "T1003.001",
       "rule_name": "LSASS Memory Access",
       "severity": "critical"
     }'
```

#### Inspect Recent Triage Results (Last 20)
```bash
curl -X GET "http://localhost:8000/results"
```
