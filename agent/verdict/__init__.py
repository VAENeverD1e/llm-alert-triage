"""
Stage 2: Verdict Agent module.
Evaluates facts against security playbooks and issues Escalate/Close verdicts with reasoning.
"""
from .evaluator import VerdictAgent

__all__ = ["VerdictAgent"]
