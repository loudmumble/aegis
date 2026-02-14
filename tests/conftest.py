"""Shared fixtures for Aegis tests."""

import pytest
from pathlib import Path

from aegis.config import (
    AegisConfig,
    OllamaConfig,
    CaptureConfig,
    CadenceConfig,
    RulesConfig,
    AlertConfig,
)
from aegis.capture.flows import FlowKey, FlowTracker, NetworkFlow, Packet


@pytest.fixture
def tmp_aegis_dir(tmp_path: Path) -> Path:
    """Create a temp directory with all aegis subdirs."""
    (tmp_path / "pcap").mkdir()
    (tmp_path / "profiles").mkdir()
    (tmp_path / "rules").mkdir()
    return tmp_path


@pytest.fixture
def aegis_config(tmp_aegis_dir: Path) -> AegisConfig:
    """Create a test-friendly config using tmp_path."""
    config = AegisConfig()
    config.capture.pcap_dir = tmp_aegis_dir / "pcap"
    config.cadence.itt_profiles_dir = tmp_aegis_dir / "profiles"
    config.rules.rules_dir = tmp_aegis_dir / "rules"
    config.alerts.json_log_path = tmp_aegis_dir / "alerts.jsonl"
    return config


def build_agent_flow(
    num_packets: int = 200,
    mean_iat_seconds: float = 0.045,
    std_iat_seconds: float = 0.003,
    src_ip: str = "10.0.0.50",
    src_port: int = 54321,
    dst_ip: str = "192.168.1.100",
    dst_port: int = 443,
) -> NetworkFlow:
    """Build a flow with agent-like (very regular) timing."""
    import random

    key = FlowKey.from_packet_fields(src_ip, src_port, dst_ip, dst_port, "tcp")
    flow = NetworkFlow(key=key)
    t = 1000000000.0

    for i in range(num_packets):
        # Every 20th packet is a forward (client) packet
        if i % 20 == 0:
            flow.add_packet(t, random.randint(100, 300), src_ip, src_port, "PA", 100)
            t += random.uniform(0.001, 0.005)
        # Rest are reverse (server streaming) packets
        iat = random.gauss(mean_iat_seconds, std_iat_seconds)
        iat = max(iat, 0.010)
        t += iat
        flow.add_packet(t, random.randint(20, 80), dst_ip, dst_port, "PA", 50)

    return flow


def build_human_flow(
    num_exchanges: int = 100,
    src_ip: str = "10.0.0.50",
    src_port: int = 54321,
    dst_ip: str = "192.168.1.100",
    dst_port: int = 443,
) -> NetworkFlow:
    """Build a flow with human-like (irregular, with think pauses) timing."""
    import random

    key = FlowKey.from_packet_fields(src_ip, src_port, dst_ip, dst_port, "tcp")
    flow = NetworkFlow(key=key)
    t = 1000000000.0

    for _ in range(num_exchanges):
        # Human think time: exponential, mean ~2s
        think_time = random.expovariate(0.5)
        think_time = min(think_time, 15.0)
        t += think_time
        flow.add_packet(t, random.randint(10, 200), src_ip, src_port, "PA", 50)

        # Server response with variable delay
        resp_delay = random.uniform(0.05, 2.0)
        t += resp_delay
        flow.add_packet(t, random.randint(50, 5000), dst_ip, dst_port, "PA", 1000)

    return flow
