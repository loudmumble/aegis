# Aegis

**Agentic Intrusion Detection & Anomaly Detection**

Aegis is a purpose-built intrusion detection framework designed to detect **agentic attacks** — attacks driven by LLM-powered autonomous agents. While traditional IDS focus on packet signatures, Aegis identifies the characteristic behavioral cadence of LLM-generated traffic, enabling the detection of malicious plans before the first harmful command is fully executed.

## Key Features

- **Cadence Analysis**: Measures Inter-Arrival Time (IAT) regularity and Coefficient of Variation (CV) to distinguish LLM-driven traffic from human interaction.
- **ITT Fingerprinting**: Identifies the specific LLM model (GPT-4o, Claude, Llama, etc.) driving an encrypted stream by analyzing token generation rhythms.
- **Transition Detection**: Automatically flags mid-session handoffs from human operators to AI agents.
- **Rule-Based Engine**: Comes with 7 built-in rules targeting agentic behavior, plus support for custom YAML rules.
- **Intent Chain Analysis**: Uses LLM reasoning (via Ollama) to correlate network flows into coherent "intent chains" (e.g., recon -> lateral movement -> exfil).
- **Multi-Output Alerting**: Routes detections to console, JSONL logs, and webhooks for SIEM integration.

## Installation

```bash
# Clone the repository
git clone https://github.com/LoudMumble/aegis
cd aegis

# Install base dependencies
pip install .

# Install ML analysis suite (numpy, scikit-learn)
pip install .[full]
```

## Quick Start

Analyze a network capture for agentic patterns:

```bash
aegis analyze /path/to/capture.pcap
```

Generate a synthetic PCAP with an agent-like cadence for testing:

```bash
aegis generate --pattern agent --output test_agent.pcap
```

List all built-in and custom detection rules:

```bash
aegis rules
```

## CLI Reference

### `aegis analyze`

Analyze a PCAP file for agentic traffic patterns.

**Arguments**:
- `PCAP_PATH`: Path to the PCAP file to scan.

**Flags**:
- `-c, --config PATH`: Path to aegis config YAML file.
- `--skip-llm`: Skip deep LLM threat analysis (cadence + rules only).
- `-v, --verbose`: Enable verbose output.

### `aegis generate`

Generate synthetic PCAP for testing cadence detection.

**Flags**:
- `-p, --pattern [agent|human|mixed]`: Traffic pattern to simulate (default: `agent`).
- `-o, --output PATH`: Output PCAP file path.

## Example Output

When an agentic shell session is detected, Aegis identifies the model and the regularity of the traffic:

```text
Phase 1: Extracting network flows...
  Extracted 4 flows
  Total packets: 1,420

Phase 2: Cadence analysis (ITT fingerprinting)...
Classification  Count
AGENT               1
HUMAN               3

  Suspicious flows (1):
    AGENT 192.168.1.50:54322 → 10.0.0.5:22 (TCP) — confidence: 92%, IAT: 42.1ms ± 7.4ms
      Model match: claude-3.5-sonnet

Phase 3: Rule evaluation...
Severity  Rule                           Flow
HIGH      LLM Streaming Cadence Detected 192.168.1.50:54322 → 10.0.0.5:22...

Phase 4: LLM threat analysis...
Threat Verdict
┌──────────────────────────────────────────────────────────────────────────┐
│ AGENTIC_ATTACK — Severity: HIGH                                          │
│ Confidence: 88%                                                          │
└──────────────────────────────────────────────────────────────────────────┘

  Detected an SSH session with inter-token timing consistent with Claude 3.5. 
  The cadence indicates automated command execution following a successful 
  authentication event.

  Intent Chains (1):
    LATERAL_MOVEMENT (confidence: 85%)
      - description: Rapid succession of directory listings and port checks
```

## Configuration

Aegis uses a YAML configuration file to manage detection thresholds and capture settings.

```yaml
ollama:
  base_url: "http://192.168.50.69:11434"
  model: "qwen3-coder:latest"

cadence:
  agent_regularity_threshold: 0.85
  human_jitter_threshold: 0.15
  min_packets_for_analysis: 20

alerts:
  json_log_path: "./aegis-data/alerts.jsonl"
  webhook_enabled: false
```

## Tech Stack

- **Language**: Python 3.10+
- **Capture**: Scapy
- **Analysis**: NumPy, SciPy, Scikit-learn
- **LLM Interface**: Ollama
- **CLI/UI**: Click, Rich

## License

MIT

## Credits

Built by LoudMumble
