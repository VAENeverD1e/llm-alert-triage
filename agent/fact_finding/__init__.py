"""
Stage 1: Fact-Finding Agent module.
Aggregates telemetry and events around an alert without making diagnostic judgments.
"""
from .collector import FactFindingAgent

__all__ = ["FactFindingAgent"]
