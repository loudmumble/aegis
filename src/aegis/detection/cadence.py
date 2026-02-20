"""Cadence analysis: the core of Aegis.

Detects LLM-driven traffic by analyzing inter-arrival time patterns.
Key insight: LLM streaming responses have characteristic timing rhythms
that differ fundamentally from human interaction patterns.

Detection methods:
1. IAT Regularity Score — measures how uniform packet spacing is
2. Coefficient of Variation — low CV = suspiciously regular (agent)
3. Autocorrelation — agents produce periodic patterns
4. Mode Clustering — LLM tokens cluster around model-specific intervals
5. Transition Detection — identifies human→agent handoff points
"""

from dataclasses import dataclass, field
from enum import Enum

import numpy as np

from ..capture.flows import NetworkFlow
from ..config import CadenceConfig


class CadenceClassification(str, Enum):
    AGENT = "agent"
    HUMAN = "human"
    MIXED = "mixed"
    UNKNOWN = "unknown"


# Known LLM model ITT profiles (mean_ms, std_ms) from research
# These are approximate fingerprints for popular models during streaming
KNOWN_MODEL_PROFILES: dict[str, tuple[float, float]] = {
    "gpt-4o": (32.0, 8.0),
    "gpt-4o-mini": (25.0, 6.0),
    "claude-3.5-sonnet": (38.0, 7.0),
    "claude-opus-4-6": (42.0, 9.0),
    "llama-3-70b": (55.0, 12.0),
    "llama-4-scout": (48.0, 10.0),
    "qwen-72b": (50.0, 11.0),
    "deepseek-v3": (40.0, 8.0),
    "ollama-local": (45.0, 15.0),  # Wide variance for local inference
}

# Known C2 beaconing profiles (mean_ms, std_ms) — second-scale intervals
# These detect command-and-control callback patterns, NOT LLM streaming
KNOWN_C2_PROFILES: dict[str, tuple[float, float]] = {
    "voidlink-aggressive": (4096.0, 819.0),  # 4096ms ± 20% jitter
    "voidlink-paranoid": (1024.0, 307.0),  # 1024ms ± 30% jitter
    "cobalt-strike-default": (60000.0, 12000.0),  # 60s ± 20%
    "cobalt-strike-fast": (5000.0, 1000.0),  # 5s ± 20%
    "generic-beacon-1s": (1000.0, 200.0),  # 1s ± 20%
    "generic-beacon-5s": (5000.0, 1000.0),  # 5s ± 20%
    "generic-beacon-30s": (30000.0, 6000.0),  # 30s ± 20%
}


@dataclass
class ModelFingerprint:
    model_name: str
    confidence: float
    mean_iat_ms: float
    profile_distance: float


@dataclass
class CadenceResult:
    """Result of cadence analysis on a single flow."""

    flow_key_str: str
    classification: CadenceClassification
    confidence: float

    # Statistical features
    mean_iat_ms: float = 0.0
    std_iat_ms: float = 0.0
    cv: float = 0.0  # Coefficient of variation
    regularity_score: float = 0.0  # 0=chaotic, 1=perfectly regular
    autocorrelation_peak: float = 0.0

    # Model fingerprinting
    model_fingerprints: list[ModelFingerprint] = field(default_factory=list)
    best_model_match: str = ""

    # Transition detection
    transition_detected: bool = False
    transition_index: int = -1

    # Raw data for downstream analysis
    packet_count: int = 0
    duration_seconds: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "flow": self.flow_key_str,
            "classification": self.classification.value,
            "confidence": round(self.confidence, 3),
            "mean_iat_ms": round(self.mean_iat_ms, 2),
            "std_iat_ms": round(self.std_iat_ms, 2),
            "cv": round(self.cv, 3),
            "regularity_score": round(self.regularity_score, 3),
            "autocorrelation_peak": round(self.autocorrelation_peak, 3),
            "best_model_match": self.best_model_match,
            "transition_detected": self.transition_detected,
            "packet_count": self.packet_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "evidence": self.evidence,
        }


class CadenceAnalyzer:
    """Analyzes network flow timing to detect LLM-driven traffic."""

    def __init__(self, config: CadenceConfig):
        self.config: CadenceConfig = config

    def analyze_flow(self, flow: NetworkFlow) -> CadenceResult | None:
        """Analyze a single flow for LLM cadence patterns.

        Returns None if the flow has insufficient data.
        """
        # Use reverse (server→client) IATs for streaming detection
        iats = flow.reverse_iats
        if len(iats) < self.config.min_packets_for_analysis:
            # Fall back to all IATs
            iats = flow.inter_arrival_times
            if len(iats) < self.config.min_packets_for_analysis:
                return None

        flow_key_str = (
            f"{flow.key.src_ip}:{flow.key.src_port}"
            + f" → {flow.key.dst_ip}:{flow.key.dst_port}"
            + f" ({flow.key.protocol})"
        )

        iat_array = np.array(iats, dtype=np.float64)

        # Core statistical features
        mean_iat = float(np.mean(iat_array))
        std_iat = float(np.std(iat_array))
        cv = std_iat / mean_iat if mean_iat > 0 else float("inf")

        regularity = self._compute_regularity(iat_array)
        autocorr_peak = self._compute_autocorrelation(iat_array)
        fingerprints = self._fingerprint_model(mean_iat, std_iat)
        transition_idx = self._detect_transition(iat_array)

        # Classification logic
        classification, confidence, evidence = self._classify(
            cv=cv,
            regularity=regularity,
            autocorr_peak=autocorr_peak,
            fingerprints=fingerprints,
            transition_idx=transition_idx,
            mean_iat=mean_iat,
            std_iat=std_iat,
            iat_array=iat_array,
        )

        return CadenceResult(
            flow_key_str=flow_key_str,
            classification=classification,
            confidence=confidence,
            mean_iat_ms=mean_iat,
            std_iat_ms=std_iat,
            cv=cv,
            regularity_score=regularity,
            autocorrelation_peak=autocorr_peak,
            model_fingerprints=fingerprints,
            best_model_match=fingerprints[0].model_name if fingerprints else "",
            transition_detected=transition_idx >= 0,
            transition_index=transition_idx,
            packet_count=flow.packet_count,
            duration_seconds=flow.duration,
            evidence=evidence,
        )

    def analyze_flows(self, flows: list[NetworkFlow]) -> list[CadenceResult]:
        """Analyze multiple flows. Returns results for flows with sufficient data."""
        results: list[CadenceResult] = []
        for flow in flows:
            result = self.analyze_flow(flow)
            if result is not None:
                results.append(result)
        return results

    @staticmethod
    def _compute_regularity(iats: np.ndarray) -> float:
        """Compute regularity score: how uniform are the inter-arrival times?

        Returns 0.0 (chaotic) to 1.0 (perfectly regular).
        Based on normalized entropy of the IAT distribution.
        """
        if len(iats) < 5:
            return 0.0

        # Bin the IATs and compute histogram entropy
        n_bins = min(50, len(iats) // 4)
        if n_bins < 3:
            return 0.0

        hist, _ = np.histogram(iats, bins=n_bins, density=True)
        hist = hist[hist > 0]
        if len(hist) == 0:
            return 0.0

        # Normalized entropy: 0 = all mass in one bin (regular), 1 = uniform
        entropy = -np.sum(hist * np.log2(hist + 1e-10)) / np.log2(n_bins)
        # Invert: high entropy = low regularity
        regularity = max(0.0, 1.0 - float(entropy))
        return regularity

    @staticmethod
    def _compute_autocorrelation(iats: np.ndarray) -> float:
        """Compute peak autocorrelation at non-zero lag.

        High autocorrelation means periodic/regular timing (agent-like).
        """
        if len(iats) < 10:
            return 0.0

        centered = iats - np.mean(iats)
        norm = np.sum(centered**2)
        if norm < 1e-10:
            return 1.0  # Perfectly regular

        max_lag = min(len(iats) // 2, 50)
        best_corr = 0.0
        for lag in range(1, max_lag):
            corr = np.sum(centered[: len(centered) - lag] * centered[lag:]) / norm
            best_corr = max(best_corr, float(corr))

        return best_corr

    def _fingerprint_model(
        self,
        mean_iat: float,
        std_iat: float,
    ) -> list[ModelFingerprint]:
        """Compare observed IAT statistics against known LLM model and C2 beaconing profiles."""
        fingerprints: list[ModelFingerprint] = []

        for model_name, (profile_mean, profile_std) in KNOWN_MODEL_PROFILES.items():
            mean_dist = abs(mean_iat - profile_mean) / max(profile_std, 1.0)
            std_dist = abs(std_iat - profile_std) / max(profile_std, 1.0)
            distance = (mean_dist**2 + std_dist**2) ** 0.5
            confidence = float(np.exp(-(distance**2) / 4.0))
            if confidence > 0.1:
                fingerprints.append(
                    ModelFingerprint(
                        model_name=model_name,
                        confidence=confidence,
                        mean_iat_ms=mean_iat,
                        profile_distance=distance,
                    )
                )

        for profile_name, (profile_mean, profile_std) in KNOWN_C2_PROFILES.items():
            mean_dist = abs(mean_iat - profile_mean) / max(profile_std, 1.0)
            std_dist = abs(std_iat - profile_std) / max(profile_std, 1.0)
            distance = (mean_dist**2 + std_dist**2) ** 0.5
            confidence = float(np.exp(-(distance**2) / 4.0))
            if confidence > 0.1:
                fingerprints.append(
                    ModelFingerprint(
                        model_name=f"c2:{profile_name}",
                        confidence=confidence,
                        mean_iat_ms=mean_iat,
                        profile_distance=distance,
                    )
                )

        fingerprints.sort(key=lambda f: f.confidence, reverse=True)
        return fingerprints[:5]

    def _detect_transition(self, iats: np.ndarray) -> int:
        """Detect human→agent transition point using sliding window CV analysis.

        Returns the index where a transition is detected, or -1.
        """
        window = self.config.itt_window_size
        if len(iats) < window * 2:
            return -1

        # Compute sliding window CV
        cvs: list[float] = []
        for i in range(len(iats) - window + 1):
            w = iats[i : i + window]
            mean = float(np.mean(w))
            std = float(np.std(w))
            cv = std / mean if mean > 0 else float("inf")
            cvs.append(cv)

        if len(cvs) < 2:
            return -1

        cv_array = np.array(cvs)

        # Look for a significant drop in CV (human → agent = high CV → low CV)
        for i in range(1, len(cv_array)):
            if cv_array[i - 1] > 0.5 and cv_array[i] < 0.2:
                # Confirm it stays low
                remaining = cv_array[i:]
                if len(remaining) >= 5 and float(np.mean(remaining[:5])) < 0.25:
                    return i + window  # Approximate packet index

        return -1

    def _classify(
        self,
        cv: float,
        regularity: float,
        autocorr_peak: float,
        fingerprints: list[ModelFingerprint],
        transition_idx: int,
        mean_iat: float,
        std_iat: float,
        iat_array: np.ndarray,
    ) -> tuple[CadenceClassification, float, list[str]]:
        """Classify flow as agent/human/mixed based on all features."""
        evidence: list[str] = []
        scores: dict[str, float] = {"agent": 0.0, "human": 0.0, "mixed": 0.0}

        # Feature 1: Coefficient of variation
        if cv < 0.15:
            scores["agent"] += 0.3
            evidence.append(f"Very low CV ({cv:.3f}) — suspiciously regular timing")
        elif cv < 0.3:
            scores["agent"] += 0.15
            evidence.append(f"Low CV ({cv:.3f}) — moderately regular")
        elif cv > 0.8:
            scores["human"] += 0.25
            evidence.append(f"High CV ({cv:.3f}) — natural timing variance")
        else:
            evidence.append(f"Moderate CV ({cv:.3f})")

        # Feature 2: Regularity score
        if regularity > self.config.agent_regularity_threshold:
            scores["agent"] += 0.25
            evidence.append(
                f"High regularity ({regularity:.3f}) — above agent threshold"
            )
        elif regularity < self.config.human_jitter_threshold:
            scores["human"] += 0.2
            evidence.append(f"Low regularity ({regularity:.3f}) — human-like jitter")

        # Feature 3: Autocorrelation
        if autocorr_peak > 0.7:
            scores["agent"] += 0.2
            evidence.append(
                f"Strong autocorrelation ({autocorr_peak:.3f}) — periodic pattern"
            )
        elif autocorr_peak < 0.2:
            scores["human"] += 0.15
            evidence.append(f"Weak autocorrelation ({autocorr_peak:.3f}) — aperiodic")

        # Feature 4: Model fingerprint match
        if fingerprints and fingerprints[0].confidence > 0.5:
            scores["agent"] += 0.2
            best = fingerprints[0]
            evidence.append(
                f"Model fingerprint match: {best.model_name} "
                + f"({best.confidence:.0%} confidence)"
            )

        # Feature 5: Transition detection
        if transition_idx >= 0:
            scores["mixed"] += 0.4
            scores["agent"] += 0.1
            evidence.append(
                f"Human→agent transition detected at packet ~{transition_idx}"
            )

        # Feature 6: IAT range check (LLMs typically 15-80ms per token)
        if 15.0 < mean_iat < 80.0 and std_iat < 20.0:
            scores["agent"] += 0.15
            evidence.append(
                f"IAT in LLM streaming range ({mean_iat:.1f}ms ± {std_iat:.1f}ms)"
            )

        # Feature 6b: C2 beaconing range (500ms-10s with moderate regularity)
        if 500.0 < mean_iat < 10000.0 and cv < 0.35:
            scores["agent"] += 0.20
            evidence.append(
                f"IAT in C2 beaconing range ({mean_iat:.0f}ms ± {std_iat:.0f}ms, CV={cv:.3f})"
            )

        # Feature 7: No long pauses (agents don't "think" between commands)
        long_pauses = int(np.sum(iat_array > 5000))  # >5s pauses
        if long_pauses > 3:
            scores["human"] += 0.2
            evidence.append(f"{long_pauses} long pauses (>5s) — human think time")
        elif long_pauses == 0 and len(iat_array) > 50:
            scores["agent"] += 0.1
            evidence.append("No long pauses in sustained session — agent-like")

        # Determine winner
        total = sum(scores.values())
        if total < 0.1:
            return CadenceClassification.UNKNOWN, 0.0, evidence

        if scores["mixed"] > scores["agent"] and scores["mixed"] > scores["human"]:
            confidence = scores["mixed"] / total
            return CadenceClassification.MIXED, min(confidence, 0.95), evidence

        if scores["agent"] > scores["human"]:
            confidence = scores["agent"] / total
            return CadenceClassification.AGENT, min(confidence, 0.95), evidence

        confidence = scores["human"] / total
        return CadenceClassification.HUMAN, min(confidence, 0.95), evidence
