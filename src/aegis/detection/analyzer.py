"""LLM-driven threat analysis and intent chain detection.

Takes cadence analysis results and flow metadata, uses an LLM to reason about
whether the detected patterns constitute a threat and what the attack intent is.
"""

import time
from dataclasses import dataclass, field
from typing import Any

from ..config import AegisConfig
from ..llm import HybridLLMClient
from ..capture.flows import NetworkFlow
from .cadence import CadenceResult, CadenceClassification


@dataclass
class IntentChain:
    """A sequence of correlated events forming an attack narrative."""

    chain_id: str
    steps: list[dict[str, str]]  # {"action": ..., "evidence": ..., "timestamp": ...}
    attack_type: str  # recon, lateral_movement, exfil, c2, persistence
    confidence: float


@dataclass
class ThreatVerdict:
    """Result of LLM-driven threat analysis."""

    severity: str  # critical, high, medium, low, info
    classification: (
        str  # agentic_attack, suspicious_automation, benign_agent, human, unknown
    )
    summary: str
    detailed_analysis: str = ""
    intent_chains: list[IntentChain] = field(default_factory=list)
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    confidence: float = 0.0
    analysis_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "classification": self.classification,
            "summary": self.summary,
            "detailed_analysis": self.detailed_analysis,
            "intent_chains": [
                {
                    "chain_id": c.chain_id,
                    "steps": c.steps,
                    "attack_type": c.attack_type,
                    "confidence": c.confidence,
                }
                for c in self.intent_chains
            ],
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
            "analysis_time": round(self.analysis_time, 2),
        }


THREAT_ANALYSIS_SYSTEM = """You are an expert network security analyst specializing in detecting AI-agent-driven attacks.
You are reviewing network flow analysis results from Aegis, an agentic intrusion detection system.

Your task: determine if the detected patterns indicate a malicious agentic attack, suspicious automation, benign AI agent usage, or normal human activity.

Key concepts:
- LLM-driven attacks produce characteristic "cadence" patterns: regular inter-token timing in encrypted traffic
- Agentic attacks follow "observe → reason → act" loops visible as traffic bursts
- Human sessions have natural jitter, think-time pauses, and irregular patterns
- Mixed sessions (human hands off to agent) show a transition point

Respond in strict JSON:
{
  "severity": "critical|high|medium|low|info",
  "classification": "agentic_attack|suspicious_automation|benign_agent|human|unknown",
  "summary": "2-3 sentence assessment",
  "detailed_analysis": "Full narrative of what you observe and why",
  "intent_chains": [
    {
      "chain_id": "chain_1",
      "steps": [
        {"action": "description", "evidence": "what data supports this", "timestamp": "relative time"}
      ],
      "attack_type": "recon|lateral_movement|exfil|c2|persistence",
      "confidence": 0.0-1.0
    }
  ],
  "mitre_techniques": [
    {"id": "T1071", "name": "Application Layer Protocol", "evidence": "why this applies"}
  ],
  "recommended_actions": [
    "Specific action to take"
  ],
  "confidence": 0.0-1.0
}"""


class ThreatAnalyzer:
    """Uses LLM reasoning to classify threats from cadence + flow data."""

    def __init__(self, config: AegisConfig, llm: HybridLLMClient):
        self.config: AegisConfig = config
        self.llm: HybridLLMClient = llm

    def analyze(
        self,
        cadence_results: list[CadenceResult],
        flows: list[NetworkFlow],
    ) -> ThreatVerdict:
        """Analyze cadence results and flows for threats."""
        start = time.time()

        # Only analyze flows flagged as agent or mixed
        suspicious = [
            r
            for r in cadence_results
            if r.classification
            in (CadenceClassification.AGENT, CadenceClassification.MIXED)
        ]

        if not suspicious:
            return ThreatVerdict(
                severity="info",
                classification="human",
                summary="No agentic traffic patterns detected. All flows appear human-driven.",
                confidence=0.9,
                analysis_time=time.time() - start,
            )

        context = self._build_analysis_context(suspicious, cadence_results, flows)

        try:
            result = self.llm.generate_json(context, THREAT_ANALYSIS_SYSTEM)
        except Exception:
            result = None

        if not result:
            return ThreatVerdict(
                severity="medium",
                classification="suspicious_automation",
                summary=f"Detected {len(suspicious)} flows with agent-like cadence "
                + "but LLM analysis unavailable for deeper assessment.",
                confidence=0.5,
                analysis_time=time.time() - start,
            )

        verdict = self._parse_verdict(result)
        verdict.analysis_time = time.time() - start
        return verdict

    def _build_analysis_context(
        self,
        suspicious: list[CadenceResult],
        all_results: list[CadenceResult],
        flows: list[NetworkFlow],
    ) -> str:
        """Build a comprehensive context string for the LLM."""
        lines: list[str] = []

        lines.append("=== AEGIS DETECTION SUMMARY ===")
        lines.append(f"Total flows analyzed: {len(all_results)}")
        lines.append(f"Suspicious flows (agent/mixed cadence): {len(suspicious)}")
        lines.append(
            f"Clean flows (human/unknown): {len(all_results) - len(suspicious)}"
        )
        lines.append("")

        for i, result in enumerate(suspicious, 1):
            lines.append(f"--- Suspicious Flow #{i} ---")
            lines.append(f"Flow: {result.flow_key_str}")
            lines.append(f"Classification: {result.classification.value}")
            lines.append(f"Confidence: {result.confidence:.0%}")
            lines.append(f"Mean IAT: {result.mean_iat_ms:.2f}ms")
            lines.append(f"Std IAT: {result.std_iat_ms:.2f}ms")
            lines.append(f"CV: {result.cv:.3f}")
            lines.append(f"Regularity Score: {result.regularity_score:.3f}")
            lines.append(f"Autocorrelation Peak: {result.autocorrelation_peak:.3f}")
            lines.append(f"Duration: {result.duration_seconds:.1f}s")
            lines.append(f"Packets: {result.packet_count}")

            if result.best_model_match:
                lines.append(f"Best Model Match: {result.best_model_match}")

            if result.transition_detected:
                lines.append(
                    f"TRANSITION DETECTED at packet ~{result.transition_index}"
                )

            lines.append("Evidence:")
            for ev in result.evidence:
                lines.append(f"  - {ev}")
            lines.append("")

        # Add flow-level network context
        lines.append("=== NETWORK CONTEXT ===")
        flow_lookup = {
            f"{f.key.src_ip}:{f.key.src_port}"
            + f" → {f.key.dst_ip}:{f.key.dst_port}"
            + f" ({f.key.protocol})": f
            for f in flows
        }
        for result in suspicious:
            flow = flow_lookup.get(result.flow_key_str)
            if flow:
                lines.append(f"Flow {result.flow_key_str}:")
                lines.append(f"  Forward bytes: {flow.total_bytes_forward:,}")
                lines.append(f"  Reverse bytes: {flow.total_bytes_reverse:,}")
                ratio = flow.total_bytes_reverse / max(flow.total_bytes_forward, 1)
                lines.append(f"  Reverse/Forward ratio: {ratio:.2f}")
                lines.append("")

        lines.append(
            "Assess these flows. Is this an agentic attack? What is the intent?"
        )

        return "\n".join(lines)

    @staticmethod
    def _parse_verdict(data: dict[str, Any]) -> ThreatVerdict:
        """Parse LLM JSON response into ThreatVerdict."""
        intent_chains: list[IntentChain] = []
        for chain_data in data.get("intent_chains", []):
            intent_chains.append(
                IntentChain(
                    chain_id=str(chain_data.get("chain_id", "")),
                    steps=chain_data.get("steps", []),
                    attack_type=str(chain_data.get("attack_type", "unknown")),
                    confidence=float(chain_data.get("confidence", 0.5)),
                )
            )

        mitre: list[dict[str, str]] = []
        for t in data.get("mitre_techniques", []):
            mitre.append(
                {
                    "id": str(t.get("id", "")),
                    "name": str(t.get("name", "")),
                    "evidence": str(t.get("evidence", "")),
                }
            )

        return ThreatVerdict(
            severity=str(data.get("severity", "medium")),
            classification=str(data.get("classification", "unknown")),
            summary=str(data.get("summary", "")),
            detailed_analysis=str(data.get("detailed_analysis", "")),
            intent_chains=intent_chains,
            mitre_techniques=mitre,
            recommended_actions=[str(a) for a in data.get("recommended_actions", [])],
            confidence=float(data.get("confidence", 0.5)),
        )
