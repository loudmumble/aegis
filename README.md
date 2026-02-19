# Aegis — Behavioral IDS for Agentic Attacks

Detect AI-driven attacks by their behavioral cadence — catches what signature-based IDS miss. Aegis identifies the characteristic rhythms of LLM-generated traffic, enabling the detection of malicious autonomous agents before they can complete their plans.

## Key Features

- **Cadence Analysis**: Measures Inter-Arrival Time (IAT) regularity to distinguish LLM-driven traffic from human interaction.
- **ITT Fingerprinting**: Identifies the specific LLM model (GPT-4o, Claude, Llama, etc.) driving an encrypted stream by analyzing token generation rhythms.
- **Transition Detection**: Automatically flags mid-session handoffs from human operators to AI agents.
- **Rule-Based Engine**: Includes built-in rules for agentic behavior and supports custom YAML-based rule definitions.
- **Intent Chain Analysis**: Uses LLM reasoning to correlate network flows into coherent "intent chains" (e.g., recon -> lateral movement -> exfil).
- **[PLANNED] eBPF Sensors**: Host-level syscall and network capture with zero user-space footprint.
- **[PLANNED] Agent Deception Layer**: Redirects identified malicious agents into synthetic honeypot environments.

## Installation

A pre-built linux/amd64 binary is in `build/`. No Python required.

```bash
# Use pre-built binary (no dependencies needed)
./build/aegis --help

# Or install from source
pip install -e .
pip install -e ".[full]"   # with ML analysis suite (numpy, scikit-learn)

# Or build a standalone binary yourself
make build          # produces build/aegis
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

## Architecture

Aegis is designed as a passive network analysis pipeline that correlates packet timing metadata with LLM behavioral models. For more details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## CLI Reference

| Command | Description |
|---------|-------------|
| `aegis analyze` | Analyze a PCAP file for agentic traffic patterns |
| `aegis generate` | Generate synthetic PCAP for testing cadence detection |
| `aegis rules` | List all built-in and custom detection rules |

### `aegis analyze` Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to aegis config YAML file | |
| `--skip-llm` | Skip deep LLM threat analysis | `False` |
| `-v, --verbose` | Enable verbose output | |

## Integration

Aegis can ingest vulnerability findings from **Phantom** to automatically update its detection rules, creating a dynamic defense loop against newly discovered attack vectors.

## License

MIT
