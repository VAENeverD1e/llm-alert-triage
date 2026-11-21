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

- **Detection**: Alerts come from Kibana detection rules in the lab; the exact rule queries are embedded in each raw alert under `data/attack_scenarios/`. `config/rules_tight.ndjson` / `rules_loose.ndjson` are reference descriptions only and are not read by the pipeline.
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
├── soc_portal/                         # SOC Analyst Web Dashboard (gitignored - not included in a clone)
│   ├── backend/                        # FastAPI dashboard endpoints
│   └── frontend/                       # Vite/React SOC operations interface
├── docs/                               # Architectural diagrams, decision logs, and proposals
│   ├── alert-schema-audit.md           # Schema audit & SIEM telemetry mapping
│   ├── evaluation_results.md           # Empirical benchmark evaluation report
│   ├── project_limitations_and_analysis.md # In-depth project critique & technical roadmap
│   └── decisions.md                    # Scope-cut log & architectural decision record (ADR)
├── config/                             # Rule definitions & agent parameters
│   ├── rules_tight.ndjson              # Reference rule descriptions with exclusions (not read by code)
│   ├── rules_loose.ndjson              # Reference rule descriptions without exclusions (not read by code)
│   └── agent_config.yaml               # Model configuration, token limits, and tool permissions
├── data/                               # Dataset & replay scenarios
│   ├── attack_scenarios/               # Raw Kibana alerts exported from the Atomic Red Team lab
│   ├── benign_scenarios/               # Hand-written, pre-normalized benign alerts (see README there)
│   └── ground_truth.jsonl              # 16 labeled alerts (8 ATK / 8 BNG); 3 benign flagged rule_would_fire=false
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
├── tests/                              # Unit & integration tests (pytest)
└── scripts/                            # Operational Scripts
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai/) installed locally (only Ollama is supported as LLM backend)
- Elasticsearch / Kibana instance (optional for local mock testing)

### Setup

1. **Clone & Setup Environment**

   ```bash
   git clone <repo-url>
   cd llm-alert-triage
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
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
# Heuristic baseline (no LLM needed)
python evaluation/replay_harness.py --mode heuristic

# LLM + RAG, 5 repeated runs (mean ± std), fixed seed
python evaluation/replay_harness.py --mode llm_rag --runs 5

# Full 5-configuration ablation suite
python evaluation/replay_harness.py --ablation-suite --runs 5

# Prompt-injection suite (default: regex guard + heuristic; add --mode llm_rag to involve the LLM)
python evaluation/prompt_injection/checker.py --mode llm_rag
```

Reports contain, besides precision/recall/F1/kappa on decided alerts:

- `coverage`, `unknown_count`, `recall_strict` — `Unknown` verdicts are not silently dropped;
- `verdict_source` per alert and `heuristic_fallback_count` / `error_fallback_count` — LLM failures are not
  counted as LLM decisions;
- `metrics_realistic_only` — excludes benign samples the real Kibana rule would never fire on;
- `metrics_by_technique`, `metrics_by_scenario_type`.

`mean_latency_ms` (alias `mttr_ms`) is pipeline/inference latency, not an operational SOC MTTR. Severity is
excluded from the prompt, Stage 1 evidence and the heuristic unless `--include-severity` is passed, and raw
Kibana alerts are stripped of workflow status, `kibana.alert.reason`, the `fields` block, host/user names and real
IPs unless `--no-sanitize` is passed.

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
