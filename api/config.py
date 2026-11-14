"""
Configuration Loader for LLM Alert Triage Service.
Loads settings from environment variables and parses config/agent_config.yaml.
"""
import os
import yaml
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

logger = logging.getLogger("APIConfig")


def _load_agent_yaml(config_path: str = "config/agent_config.yaml") -> Dict[str, Any]:
    """Reads agent_config.yaml if present."""
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                logger.info(f"Loaded YAML configuration from {config_path}")
                return data
        except Exception as e:
            logger.warning(f"Failed to parse {config_path}: {e}")
    return {}


@dataclass
class APISettings:
    """Consolidated configuration combining YAML parameters and Environment overrides."""
    # YAML raw dict
    yaml_config: Dict[str, Any] = field(default_factory=lambda: _load_agent_yaml())

    # Metadata
    api_title: str = "LLM Security Alert Triage API"
    api_version: str = "1.0.0"
    api_description: str = (
        "Production-grade triage API receiving raw Elasticsearch / Kibana SIEM alerts, "
        "executing two-stage LLM triage (Fact-Finding + RAG Playbook Verdict), "
        "and dispatching rich color-coded verdict notifications to Discord."
    )

    # Server network
    host: str = os.getenv("API_HOST", "0.0.0.0")
    port: int = int(os.getenv("API_PORT", "8000"))

    # Webhook Authentication Secret (Kibana X-Webhook-Secret or Authorization header)
    webhook_secret: str = os.getenv("WEBHOOK_SECRET", "")

    # Elasticsearch connection
    elastic_url: str = os.getenv("ELASTIC_URL", "http://192.168.31.130:9200")
    elastic_api_key: str = os.getenv("ELASTIC_API_KEY", "")
    elastic_verify_ssl: bool = os.getenv("ELASTIC_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
    elastic_alert_index: str = os.getenv("ELASTIC_ALERT_INDEX", ".alerts-security.alerts-*")

    # Elasticsearch Polling (thay thế Kibana webhook connector khi không có Gold license)
    elastic_poll_enabled: bool = os.getenv("ELASTIC_POLL_ENABLED", "true").lower() in ("true", "1", "yes")
    elastic_poll_interval: int = int(os.getenv("ELASTIC_POLL_INTERVAL", "30"))

    # Discord Notification Settings
    discord_webhook_url: str = os.getenv("DISCORD_WEBHOOK_URL", "")
    discord_dry_run: bool = os.getenv("DISCORD_DRY_RUN", "false").lower() in ("true", "1", "yes")
    discord_timeout: float = float(os.getenv("DISCORD_TIMEOUT", "5.0"))
    discord_retry_count: int = int(os.getenv("DISCORD_RETRY_COUNT", "2"))

    # RAG Settings
    use_rag: bool = os.getenv("USE_RAG", "true").lower() in ("true", "1", "yes")
    playbooks_dir: str = os.getenv("PLAYBOOKS_DIR", "./playbooks")

    # LLM Settings (derived from YAML models.primary with ENV overrides)
    use_ollama: bool = os.getenv("USE_OLLAMA", "true").lower() in ("true", "1", "yes")
    ollama_model: str = ""
    ollama_host: str = ""
    ollama_timeout: int = 30

    # Pipeline Thresholds
    confidence_threshold_escalate: float = 0.70
    confidence_threshold_close: float = 0.85
    default_action_on_failure: str = "Escalate"
    max_history_entries: int = int(os.getenv("MAX_HISTORY_ENTRIES", "50"))

    def __post_init__(self):
        # Extract model configuration from YAML
        primary_model = self.yaml_config.get("models", {}).get("primary", {})
        yaml_model_name = primary_model.get("model_name", "llama3:8b")
        yaml_host = primary_model.get("base_url", "http://localhost:11434")
        yaml_timeout = primary_model.get("timeout_seconds", 30)

        # Environment variables take precedence over YAML
        self.ollama_model = os.getenv("OLLAMA_MODEL", yaml_model_name)
        self.ollama_host = os.getenv("OLLAMA_HOST", yaml_host)
        self.ollama_timeout = int(os.getenv("OLLAMA_TIMEOUT", str(yaml_timeout)))

        # Extract pipeline parameters from YAML
        pipeline_cfg = self.yaml_config.get("pipeline", {})
        self.confidence_threshold_escalate = float(pipeline_cfg.get("confidence_threshold_escalate", 0.70))
        self.confidence_threshold_close = float(pipeline_cfg.get("confidence_threshold_close", 0.85))
        self.default_action_on_failure = pipeline_cfg.get("default_action_on_failure", "Escalate")


# Singleton instance
settings = APISettings()
