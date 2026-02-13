"""Alert pipeline: routes detection results to multiple outputs."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import AlertConfig
from ..detection.cadence import CadenceResult
from ..detection.rules import RuleMatch
from ..detection.analyzer import ThreatVerdict


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Alert:
    """A structured alert ready for output."""

    alert_id: str
    timestamp: str
    severity: str
    title: str
    description: str
    flow: str
    rule_matches: list[dict[str, Any]] = field(default_factory=list)
    cadence_data: dict[str, Any] = field(default_factory=dict)
    threat_verdict: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "flow": self.flow,
            "rule_matches": self.rule_matches,
            "cadence": self.cadence_data,
            "threat": self.threat_verdict,
            "evidence": self.evidence,
        }


class AlertPipeline:
    """Routes alerts to console, JSON log, and webhooks."""

    def __init__(self, config: AlertConfig):
        self.config: AlertConfig = config
        self._alert_counter: int = 0

    def process(
        self,
        cadence_results: list[CadenceResult],
        rule_matches: list[RuleMatch],
        threat_verdict: ThreatVerdict | None = None,
    ) -> list[Alert]:
        """Process detection results into alerts and route to outputs."""
        alerts: list[Alert] = []

        # Group rule matches by flow
        flow_matches: dict[str, list[RuleMatch]] = {}
        for match in rule_matches:
            flow_matches.setdefault(match.flow_key, []).append(match)

        # Build cadence lookup
        cadence_map: dict[str, CadenceResult] = {}
        for cr in cadence_results:
            cadence_map[cr.flow_key_str] = cr

        # Create one alert per suspicious flow
        for flow_key, matches in flow_matches.items():
            highest_severity = min(
                (SEVERITY_ORDER.get(m.severity, 4) for m in matches),
                default=4,
            )
            severity_name = next(
                k for k, v in SEVERITY_ORDER.items() if v == highest_severity
            )

            # Skip if below minimum severity
            if highest_severity > SEVERITY_ORDER.get(self.config.min_severity, 3):
                continue

            self._alert_counter += 1
            now = datetime.now(timezone.utc)
            alert_id = f"AEGIS-{now.strftime('%Y%m%d')}-{self._alert_counter:04d}"

            # Build alert title from highest-severity rule
            top_match = min(matches, key=lambda m: SEVERITY_ORDER.get(m.severity, 4))
            cadence = cadence_map.get(flow_key)

            evidence: list[str] = []
            if cadence:
                evidence.extend(cadence.evidence)
            for m in matches:
                evidence.extend(m.matched_conditions)

            alert = Alert(
                alert_id=alert_id,
                timestamp=now.isoformat(),
                severity=severity_name,
                title=top_match.rule.name,
                description=top_match.details,
                flow=flow_key,
                rule_matches=[m.to_dict() for m in matches],
                cadence_data=cadence.to_dict() if cadence else {},
                threat_verdict=threat_verdict.to_dict() if threat_verdict else {},
                evidence=evidence,
            )
            alerts.append(alert)

        # Route to outputs
        for alert in alerts:
            if self.config.json_log_enabled:
                self._write_json_log(alert)
            if self.config.webhook_enabled and self.config.webhook_url:
                self._send_webhook(alert)

        return alerts

    def _write_json_log(self, alert: Alert) -> None:
        """Append alert to JSONL log file."""
        log_path = self.config.json_log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    def _send_webhook(self, alert: Alert) -> None:
        """Send alert to configured webhook URL."""
        try:
            httpx.post(
                self.config.webhook_url,
                json=alert.to_dict(),
                timeout=10.0,
            )
        except Exception:
            pass  # Best-effort delivery
