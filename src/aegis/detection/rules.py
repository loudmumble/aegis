"""Agent-specific detection rules inspired by Sigma format.

Rules detect patterns specific to agentic attacks that traditional IDS misses:
- Too-regular command timing
- LLM API correlation patterns
- Reconnaissance cadence
- Tool-use loops
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..capture.flows import NetworkFlow
from .cadence import CadenceResult


@dataclass
class Rule:
    """A detection rule."""

    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low, info
    tags: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            severity=str(data.get("severity", "medium")),
            tags=data.get("tags", []),
            conditions=data.get("conditions", {}),
            enabled=data.get("enabled", True),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "tags": self.tags,
            "conditions": self.conditions,
            "enabled": self.enabled,
        }


@dataclass
class RuleMatch:
    """A rule that matched against a flow."""

    rule: Rule
    flow_key: str
    matched_conditions: list[str]
    severity: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.severity,
            "flow": self.flow_key,
            "matched_conditions": self.matched_conditions,
            "details": self.details,
        }


# Built-in rules for agentic attack detection
BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "id": "AEGIS-001",
        "name": "LLM Streaming Cadence Detected",
        "description": "Flow exhibits inter-arrival timing consistent with LLM token streaming. "
        "This indicates AI-generated traffic, which may be benign (coding assistant) "
        "or malicious (agent-driven attack).",
        "severity": "medium",
        "tags": ["cadence", "llm", "streaming"],
        "conditions": {
            "classification": "agent",
            "min_confidence": 0.6,
            "mean_iat_range": [15, 80],
            "cv_max": 0.3,
        },
    },
    {
        "id": "AEGIS-002",
        "name": "High-Confidence Agent Traffic",
        "description": "Flow shows strong evidence of LLM agent activity with high confidence "
        "model fingerprint match. Investigate for unauthorized AI tool usage.",
        "severity": "high",
        "tags": ["cadence", "llm", "high-confidence"],
        "conditions": {
            "classification": "agent",
            "min_confidence": 0.8,
            "has_model_match": True,
        },
    },
    {
        "id": "AEGIS-003",
        "name": "Human-to-Agent Transition",
        "description": "Session exhibits a transition from human-like timing to agent-like timing. "
        "This pattern is characteristic of an attacker handing off to an AI agent "
        "mid-session (e.g., after initial access).",
        "severity": "high",
        "tags": ["cadence", "transition", "handoff"],
        "conditions": {
            "classification": "mixed",
            "transition_detected": True,
        },
    },
    {
        "id": "AEGIS-004",
        "name": "Sustained Agent Session",
        "description": "Agent-classified flow has been active for an extended period, suggesting "
        "an autonomous operation (recon, lateral movement, or data collection).",
        "severity": "high",
        "tags": ["cadence", "sustained", "autonomous"],
        "conditions": {
            "classification": "agent",
            "min_confidence": 0.6,
            "min_duration_seconds": 120,
            "min_packets": 200,
        },
    },
    {
        "id": "AEGIS-005",
        "name": "Perfectly Regular Traffic",
        "description": "Traffic shows near-zero timing variance — unnaturally regular. "
        "No human produces this pattern. Strong indicator of automated/scripted activity.",
        "severity": "medium",
        "tags": ["cadence", "automation", "regularity"],
        "conditions": {
            "regularity_min": 0.9,
            "cv_max": 0.1,
        },
    },
    {
        "id": "AEGIS-006",
        "name": "Known LLM Model in Encrypted Traffic",
        "description": "Inter-token timing fingerprint matches a known LLM model in encrypted traffic. "
        "The model may be running commands on the target system.",
        "severity": "medium",
        "tags": ["fingerprint", "itt", "model-detection"],
        "conditions": {
            "has_model_match": True,
            "model_confidence_min": 0.7,
        },
    },
    {
        "id": "AEGIS-007",
        "name": "High-Volume Agent Data Transfer",
        "description": "Agent-classified flow has transferred a large amount of data, "
        "suggesting exfiltration or bulk data collection.",
        "severity": "critical",
        "tags": ["exfiltration", "volume", "agent"],
        "conditions": {
            "classification": "agent",
            "min_confidence": 0.6,
            "min_bytes": 1_000_000,
        },
    },
    {
        "id": "AEGIS-008",
        "name": "C2 Beaconing Pattern",
        "description": "Flow exhibits periodic timing consistent with C2 beacon callbacks. "
        "Second-scale intervals (500ms-10s) with low jitter indicate automated C2 communication, "
        "not human activity or LLM streaming.",
        "severity": "high",
        "tags": ["cadence", "c2", "beaconing"],
        "conditions": {
            "mean_iat_range": [500, 10000],
            "cv_max": 0.30,
            "regularity_min": 0.70,
        },
    },
    {
        "id": "AEGIS-009",
        "name": "Periodic Network Beaconing",
        "description": "Strong autocorrelation at second-scale intervals indicates periodic network callbacks. "
        "Combined with beaconing-range timing, this is a high-confidence C2 indicator.",
        "severity": "high",
        "tags": ["cadence", "c2", "autocorrelation", "beaconing"],
        "conditions": {
            "autocorrelation_min": 0.70,
            "mean_iat_range": [500, 10000],
        },
    },
]


class RuleEngine:
    """Evaluates detection rules against flow analysis results."""

    def __init__(self, rules_dir: Path | None = None, builtin_enabled: bool = True):
        self.rules: list[Rule] = []
        if builtin_enabled:
            for rule_data in BUILTIN_RULES:
                self.rules.append(Rule.from_dict(rule_data))
        if rules_dir and rules_dir.exists():
            self._load_custom_rules(rules_dir)

    def _load_custom_rules(self, rules_dir: Path) -> None:
        """Load YAML rule files from a directory."""
        for rule_file in sorted(rules_dir.glob("*.yml")):
            try:
                with open(rule_file) as f:
                    data = yaml.safe_load(f)
                if isinstance(data, list):
                    for item in data:
                        self.rules.append(Rule.from_dict(item))
                elif isinstance(data, dict):
                    self.rules.append(Rule.from_dict(data))
            except Exception:
                continue  # Skip malformed rule files

    def evaluate(
        self,
        cadence_result: CadenceResult,
        flow: NetworkFlow | None = None,
    ) -> list[RuleMatch]:
        """Evaluate all rules against a single flow analysis result."""
        matches: list[RuleMatch] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            matched_conditions: list[str] = []
            all_match = True

            cond = rule.conditions

            # Classification check
            if "classification" in cond:
                if cadence_result.classification.value == cond["classification"]:
                    matched_conditions.append(
                        f"classification={cond['classification']}"
                    )
                else:
                    all_match = False
                    continue

            # Confidence check
            if "min_confidence" in cond:
                if cadence_result.confidence >= cond["min_confidence"]:
                    matched_conditions.append(
                        f"confidence={cadence_result.confidence:.2f}"
                        + f"≥{cond['min_confidence']}"
                    )
                else:
                    all_match = False
                    continue

            # IAT range check
            if "mean_iat_range" in cond:
                low, high = cond["mean_iat_range"]
                if low <= cadence_result.mean_iat_ms <= high:
                    matched_conditions.append(
                        f"mean_iat={cadence_result.mean_iat_ms:.1f}ms "
                        + f"in [{low},{high}]"
                    )
                else:
                    all_match = False
                    continue

            # CV check
            if "cv_max" in cond:
                if cadence_result.cv <= cond["cv_max"]:
                    matched_conditions.append(
                        f"cv={cadence_result.cv:.3f}≤{cond['cv_max']}"
                    )
                else:
                    all_match = False
                    continue

            # Model match check
            if "has_model_match" in cond and cond["has_model_match"]:
                if cadence_result.best_model_match:
                    matched_conditions.append(
                        f"model_match={cadence_result.best_model_match}"
                    )
                else:
                    all_match = False
                    continue

            # Model confidence check
            if "model_confidence_min" in cond:
                top_conf = (
                    cadence_result.model_fingerprints[0].confidence
                    if cadence_result.model_fingerprints
                    else 0.0
                )
                if top_conf >= cond["model_confidence_min"]:
                    matched_conditions.append(f"model_confidence={top_conf:.2f}")
                else:
                    all_match = False
                    continue

            # Transition check
            if "transition_detected" in cond:
                if cadence_result.transition_detected == cond["transition_detected"]:
                    matched_conditions.append("transition_detected")
                else:
                    all_match = False
                    continue

            # Duration check
            if "min_duration_seconds" in cond:
                if cadence_result.duration_seconds >= cond["min_duration_seconds"]:
                    matched_conditions.append(
                        f"duration={cadence_result.duration_seconds:.0f}s"
                    )
                else:
                    all_match = False
                    continue

            # Packet count check
            if "min_packets" in cond:
                if cadence_result.packet_count >= cond["min_packets"]:
                    matched_conditions.append(f"packets={cadence_result.packet_count}")
                else:
                    all_match = False
                    continue

            # Regularity check
            if "regularity_min" in cond:
                if cadence_result.regularity_score >= cond["regularity_min"]:
                    matched_conditions.append(
                        f"regularity={cadence_result.regularity_score:.3f}"
                    )
                else:
                    all_match = False
                    continue

            # Autocorrelation check
            if "autocorrelation_min" in cond:
                if cadence_result.autocorrelation_peak >= cond["autocorrelation_min"]:
                    matched_conditions.append(
                        f"autocorrelation={cadence_result.autocorrelation_peak:.3f}"
                    )
                else:
                    all_match = False
                    continue

            # Byte volume check (requires flow)
            if "min_bytes" in cond and flow:
                total = flow.total_bytes_forward + flow.total_bytes_reverse
                if total >= cond["min_bytes"]:
                    matched_conditions.append(f"bytes={total:,}")
                else:
                    all_match = False
                    continue

            if all_match and matched_conditions:
                matches.append(
                    RuleMatch(
                        rule=rule,
                        flow_key=cadence_result.flow_key_str,
                        matched_conditions=matched_conditions,
                        severity=rule.severity,
                        details=rule.description,
                    )
                )

        return matches

    def evaluate_all(
        self,
        cadence_results: list[CadenceResult],
        flows: list[NetworkFlow] | None = None,
    ) -> list[RuleMatch]:
        """Evaluate all rules against all flows."""
        all_matches: list[RuleMatch] = []

        flow_map: dict[str, NetworkFlow] = {}
        if flows:
            for f in flows:
                key_str = (
                    f"{f.key.src_ip}:{f.key.src_port}"
                    + f" → {f.key.dst_ip}:{f.key.dst_port}"
                    + f" ({f.key.protocol})"
                )
                flow_map[key_str] = f

        for result in cadence_results:
            flow = flow_map.get(result.flow_key_str)
            matches = self.evaluate(result, flow)
            all_matches.extend(matches)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_matches.sort(key=lambda m: severity_order.get(m.severity, 5))

        return all_matches
