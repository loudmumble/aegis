"""Network flow tracking and packet timing extraction.

Captures the raw data needed for cadence analysis: per-packet timestamps, sizes,
and directionality within TCP/UDP flows.
"""

import time
from dataclasses import dataclass, field
from typing import NamedTuple


class FlowKey(NamedTuple):
    """Bidirectional flow identifier (sorted so A→B and B→A share a key)."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    @classmethod
    def from_packet_fields(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> "FlowKey":
        """Create a canonical (sorted) flow key so both directions map to same flow."""
        if (src_ip, src_port) > (dst_ip, dst_port):
            return cls(dst_ip, dst_port, src_ip, src_port, protocol)
        return cls(src_ip, src_port, dst_ip, dst_port, protocol)


@dataclass
class Packet:
    """A single observed packet within a flow."""

    timestamp: float
    size: int
    direction: str  # "forward" (src→dst) or "reverse" (dst→src)
    flags: str = ""  # TCP flags: SYN, ACK, PSH, FIN, RST
    payload_size: int = 0


@dataclass
class NetworkFlow:
    """A bidirectional network flow with timing data."""

    key: FlowKey
    packets: list[Packet] = field(default_factory=list)
    start_time: float = 0.0
    last_seen: float = 0.0
    total_bytes_forward: int = 0
    total_bytes_reverse: int = 0
    is_complete: bool = False

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time if self.start_time > 0 else 0.0

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def forward_packets(self) -> list[Packet]:
        return [p for p in self.packets if p.direction == "forward"]

    @property
    def reverse_packets(self) -> list[Packet]:
        return [p for p in self.packets if p.direction == "reverse"]

    @property
    def inter_arrival_times(self) -> list[float]:
        """All inter-arrival times in milliseconds."""
        if len(self.packets) < 2:
            return []
        iats: list[float] = []
        for i in range(1, len(self.packets)):
            delta = (self.packets[i].timestamp - self.packets[i - 1].timestamp) * 1000
            iats.append(delta)
        return iats

    @property
    def forward_iats(self) -> list[float]:
        """Inter-arrival times for forward direction only (ms)."""
        fwd = self.forward_packets
        if len(fwd) < 2:
            return []
        return [
            (fwd[i].timestamp - fwd[i - 1].timestamp) * 1000 for i in range(1, len(fwd))
        ]

    @property
    def reverse_iats(self) -> list[float]:
        """Inter-arrival times for reverse direction only (ms) — key for ITT analysis."""
        rev = self.reverse_packets
        if len(rev) < 2:
            return []
        return [
            (rev[i].timestamp - rev[i - 1].timestamp) * 1000 for i in range(1, len(rev))
        ]

    def add_packet(
        self,
        timestamp: float,
        size: int,
        src_ip: str,
        src_port: int,
        flags: str = "",
        payload_size: int = 0,
    ) -> None:
        """Add a packet to this flow, determining direction automatically."""
        if src_ip == self.key.src_ip and src_port == self.key.src_port:
            direction = "forward"
            self.total_bytes_forward += size
        else:
            direction = "reverse"
            self.total_bytes_reverse += size

        pkt = Packet(
            timestamp=timestamp,
            size=size,
            direction=direction,
            flags=flags,
            payload_size=payload_size,
        )
        self.packets.append(pkt)

        if self.start_time == 0.0:
            self.start_time = timestamp
        self.last_seen = timestamp

        if "FIN" in flags or "RST" in flags:
            self.is_complete = True

    def to_dict(self) -> dict:
        """Serialize for JSON export."""
        return {
            "flow_key": {
                "src_ip": self.key.src_ip,
                "src_port": self.key.src_port,
                "dst_ip": self.key.dst_ip,
                "dst_port": self.key.dst_port,
                "protocol": self.key.protocol,
            },
            "start_time": self.start_time,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "forward_packets": len(self.forward_packets),
            "reverse_packets": len(self.reverse_packets),
            "total_bytes_forward": self.total_bytes_forward,
            "total_bytes_reverse": self.total_bytes_reverse,
            "is_complete": self.is_complete,
        }


class FlowTracker:
    """Tracks active network flows and extracts timing data."""

    def __init__(self, flow_timeout: float = 30.0):
        self.flows: dict[FlowKey, NetworkFlow] = {}
        self.flow_timeout: float = flow_timeout
        self.completed_flows: list[NetworkFlow] = []

    def process_packet(
        self,
        timestamp: float,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        size: int,
        flags: str = "",
        payload_size: int = 0,
    ) -> NetworkFlow:
        """Process a packet and return its flow."""
        key = FlowKey.from_packet_fields(src_ip, src_port, dst_ip, dst_port, protocol)

        if key not in self.flows:
            self.flows[key] = NetworkFlow(key=key)

        flow = self.flows[key]
        flow.add_packet(timestamp, size, src_ip, src_port, flags, payload_size)

        if flow.is_complete:
            self.completed_flows.append(flow)
            del self.flows[key]

        return flow

    def expire_flows(self, current_time: float | None = None) -> list[NetworkFlow]:
        """Expire flows that have been idle too long."""
        now = current_time or time.time()
        expired: list[NetworkFlow] = []
        keys_to_remove: list[FlowKey] = []

        for key, flow in self.flows.items():
            if now - flow.last_seen > self.flow_timeout:
                flow.is_complete = True
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.flows[key]

        self.completed_flows.extend(expired)
        return expired

    def get_active_flows(self) -> list[NetworkFlow]:
        """Return all currently active (non-expired) flows."""
        return list(self.flows.values())

    def get_analyzable_flows(self, min_packets: int = 20) -> list[NetworkFlow]:
        """Return active flows with enough packets for cadence analysis."""
        return [f for f in self.flows.values() if f.packet_count >= min_packets]

    @property
    def stats(self) -> dict[str, int]:
        return {
            "active_flows": len(self.flows),
            "completed_flows": len(self.completed_flows),
            "total_packets": sum(
                f.packet_count for f in list(self.flows.values()) + self.completed_flows
            ),
        }
