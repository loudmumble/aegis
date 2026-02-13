# Aegis Architecture

## System Overview

Aegis is designed as a passive network analysis pipeline that correlates packet timing metadata with LLM behavioral models.

```text
┌─────────────────────────────────────────────────────┐
│                    AEGIS CORE                       │
│                                                     │
│  ┌────────────┐      ┌──────────────┐      ┌─────┐  │
│  │   Capture  │      │    Cadence   │      │ LLM │  │
│  │   Reader   ├─────►│    Analyzer  ├─────►│Pass │  │
│  │  (Scapy)   │      │   (ITT/IAT)  │      │  1  │  │
│  └────────────┘      └──────┬───────┘      └─────┘  │
│                             │                 │     │
│                             │                 ▼     │
│                             │              ┌─────┐  │
│                             └─────────────►│Alert│  │
│                                            │Pipe │  │
│                                            │line │  │
│                                            └─────┘  │
│                                               │     │
│  ┌─────────────────────────────────────────┐  ▼     │
│  │               OUTPUT                    │┌─────┐ │
│  │  (Console, JSONL, Webhooks)             │┤ SIEM│ │
│  └─────────────────────────────────────────┘└─────┘ │
└─────────────────────────────────────────────────────┘
```

## Component Descriptions

### `aegis.capture`
The capture layer is responsible for ingesting network data.
- **`FlowTracker`**: Groups packets into bidirectional flows using 5-tuple keys (src_ip, src_port, dst_ip, dst_port, protocol). It maintains state for active flows and extracts precise inter-arrival times (IATs).
- **`PcapReader`**: Interface for reading raw PCAP files and feeding them to the `FlowTracker`.

### `aegis.detection.cadence`
The core logic of Aegis. It analyzes the timing of server-to-client packets (which correspond to LLM token generation).
- **Regularity Score**: Uses normalized entropy to measure how periodic the packet timing is. High regularity is a strong indicator of machine-generated output.
- **Coefficient of Variation (CV)**: Calculates the ratio of standard deviation to mean IAT. LLM streams typically show very low CV compared to human terminal interaction.
- **Model Fingerprinting**: Compares observed statistics against a library of `KNOWN_MODEL_PROFILES` (e.g., GPT-4o, Claude 3.5) to identify the model type.

### `aegis.detection.rules`
A signature-like layer that evaluates high-level patterns across multiple flows.
- **Built-in Rules**: 7 rules covering streaming cadence, handoff detection, and high-volume agent exfiltration.
- **Custom Rules**: Supports YAML-based rule definitions with conditions for classification, confidence, IAT range, and duration.

### `aegis.detection.analyzer`
The LLM reasoning module. It takes the output of the cadence analysis and the raw flow metadata to build an attack narrative.
- **Intent Chains**: Groups correlated actions into logical sequences (Recon, Lateral Movement, etc.).
- **MITRE Mapping**: Identifies relevant ATT&CK techniques based on the observed cadence and flow volumes.

### `aegis.alerting`
The `AlertPipeline` handles deduplication, severity prioritization, and output routing. It ensures that multiple rule hits on the same flow are collapsed into a single actionable alert.

## Data Flow

1. **Extraction**: Packets are read and grouped into `NetworkFlow` objects.
2. **Cadence Pass**: For every flow with >20 packets, the `CadenceAnalyzer` calculates statistical features and model matches.
3. **Rule Pass**: The `RuleEngine` checks for specific triggers (e.g., human-to-agent transition).
4. **Threat Pass**: Suspicious flows are synthesized into a prompt for the LLM to identify the "intent chain."
5. **Alerting**: Detections are logged and forwarded to external handlers.

## LLM Integration

Aegis uses the **qwen3-coder** model to perform "semantic IDS" functions.

- **Model Fingerprinting**: While initial fingerprinting is statistical, the LLM verifies the likelihood of a specific model being used for an attack.
- **Intent Correlation**: The LLM is uniquely capable of understanding that a sequence of distinct flows (e.g., a port scan followed by a regular cadence shell) forms a single agentic campaign.

## Extension Points

- **Model Profiles**: Add new (mean, std) tuples to `KNOWN_MODEL_PROFILES` in `cadence.py` as new LLM versions are released.
- **Rule Definitions**: Create new YAML files in `./aegis-data/rules/` to detect environment-specific agent behaviors.
- **Alert Handlers**: Extend `pipeline.py` to support new outputs like Slack, Teams, or PagerDuty.

## Performance Considerations

- **Statistical Pre-filtering**: LLM reasoning is only triggered for flows that pass the statistical "agent-like" threshold, significantly reducing model costs and latency.
- **NumPy Optimization**: All timing calculations are vectorized using NumPy for high-throughput PCAP processing.
- **Stateless Analysis**: The core analyzer is stateless, allowing for easy parallelization across large capture files.

## Dependencies

- **scapy**: The industry standard for network packet manipulation and dissection.
- **numpy**: Critical for fast statistical analysis of inter-arrival times.
- **httpx**: Used for low-latency communication with the Ollama API.
