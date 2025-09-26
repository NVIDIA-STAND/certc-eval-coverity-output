"""Utility helpers for the CERT-C evaluator UI."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
PRIORITY_OPTIONS = [f"P{i}" for i in range(1, 19)]
CERT_C_RULES_PATH = "cert-c/certc_rules.json"
COVERITY_EXAMPLES_PATH = "coverity/example_inputs.json"
RUBRIC_PATH = "evaluator/rubric.json"

def normalize(value: Optional[str]) -> str:
    """Normalize a possibly missing string before downstream analysis."""
    return (value or "").strip()

def join_nonempty(parts: List[str], sep: str = "\n\n") -> str:
    """Join non-empty strings while preserving relative order."""
    return sep.join([p for p in parts if p and p.strip()])

def load_rules(path: str = CERT_C_RULES_PATH) -> List[Dict[str, Any]]:
    """Load CERT-C rule definitions from disk."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data = [data]
    return [rule for rule in data if rule.get("rule_id") and rule.get("title")]

def rule_index_by_id(rules: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index rules by their identifier for quick lookup."""
    return {rule["rule_id"]: rule for rule in rules if rule.get("rule_id")}

def load_examples(path: str = COVERITY_EXAMPLES_PATH) -> List[Dict[str, Any]]:
    """Load example Coverity/AI pairs from disk."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data = [data]
    return data


def load_rubric(path: str = RUBRIC_PATH) -> Dict[str, Any]:
    """Load the evaluation rubric definition from disk."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Rubric JSON must contain an object at the top level")
    return data
