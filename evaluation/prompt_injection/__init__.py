"""
Prompt Injection Evaluation Package.
Tests adversarial prompt injection robustness in telemetry alert fields.
"""
from .checker import PromptInjectionChecker

__all__ = ["PromptInjectionChecker"]
