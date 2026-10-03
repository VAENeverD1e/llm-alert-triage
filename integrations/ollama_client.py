"""
Ollama Local LLM Client Integration.
Handles inference requests to local models (Llama 3, Mistral, Qwen) via HTTP API.
"""
import logging
import json
from typing import Dict, Any, Optional, List
import requests

logger = logging.getLogger(__name__)


class OllamaClient:
    """
    Client for interacting with local Ollama server instances.
    Supports both direct prompt generation and multi-turn chat completions,
    with built-in JSON schema enforcement and graceful fallback handling.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_name: str = "llama3:8b",
        timeout: float = 180.0
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout = timeout
        logger.info(f"Initialized OllamaClient: base_url={self.base_url}, model={self.model_name}")

    def is_alive(self) -> bool:
        """
        Checks if the local Ollama server is running and accessible.
        """
        try:
            res = requests.get(f"{self.base_url}/api/tags", timeout=3.0)
            return res.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """
        Returns a list of model names currently pulled and available in Ollama.
        """
        try:
            res = requests.get(f"{self.base_url}/api/tags", timeout=5.0)
            if res.status_code == 200:
                models_data = res.json().get("models", [])
                return [m.get("name") for m in models_data if "name" in m]
            return []
        except Exception as e:
            logger.warning(f"Failed to fetch model list from Ollama: {e}")
            return []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.1,
        fallback_mock: bool = True
    ) -> str:
        """
        Sends generation request to local Ollama instance (/api/generate).
        
        Args:
            prompt: User/task prompt.
            system_prompt: Optional system instructions.
            json_format: If True, instructs Ollama to enforce structured JSON output.
            temperature: Sampling temperature (lower = more deterministic for triage).
            fallback_mock: If True and Ollama is unreachable, returns a deterministic mock payload.
        """
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        if system_prompt:
            payload["system"] = system_prompt
        if json_format:
            payload["format"] = "json"

        try:
            logger.info(f"Sending generate request to Ollama ({self.model_name})...")
            res = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            res.raise_for_status()
            data = res.json()
            return data.get("response", "")
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            if fallback_mock:
                logger.warning("Ollama server unreachable or error occurred. Using mock fallback response.")
                return self._generate_fallback(prompt, json_format)
            raise

    def chat(
        self,
        messages: List[Dict[str, str]],
        json_format: bool = False,
        temperature: float = 0.1,
        fallback_mock: bool = True
    ) -> str:
        """
        Sends multi-turn chat request to local Ollama instance (/api/chat).
        """
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        if json_format:
            payload["format"] = "json"

        try:
            logger.info(f"Sending chat request to Ollama ({self.model_name})...")
            res = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            res.raise_for_status()
            data = res.json()
            return data.get("message", {}).get("content", "")
        except Exception as e:
            logger.error(f"Ollama chat failed: {e}")
            if fallback_mock:
                logger.warning("Ollama server unreachable or error occurred. Using mock fallback response.")
                last_msg = messages[-1]["content"] if messages else ""
                return self._generate_fallback(last_msg, json_format)
            raise

    def _generate_fallback(self, prompt: str, json_format: bool) -> str:
        """
        Provides a structured fallback response for offline testing and CI workflows.
        """
        if json_format:
            # Deterministic JSON mock mimicking VerdictOutput
            mock_data = {
                "decision": "ESCALATE",
                "confidence_score": 0.88,
                "reasoning": "Fallback reasoning: suspicious behavior detected in alert parameters.",
                "recommended_playbook": "PB-Default",
                "mitre_attack_techniques": [],
                "risk_factors": ["High alert severity", "Anomalous process tree"]
            }
            return json.dumps(mock_data)
        return "Mock response from Ollama model."
