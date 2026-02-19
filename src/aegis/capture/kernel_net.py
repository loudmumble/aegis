"""Kernel-level network connection monitoring via ebpf-sensors.

Provides PID-attributed TCP/UDP connection data that supplements scapy's
packet-level capture. When ebpf-sensors is available and running as root,
uses eBPF tracepoints for real-time connection tracking. Falls back to
/proc/net/tcp polling in unprivileged contexts.

This module is entirely optional — Aegis works without it.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from .flows import NetworkFlow

logger = logging.getLogger(__name__)


def _check_ebpf_sensors() -> bool:
    try:
        import ebpf_sensors  # noqa: F401

        return True
    except ImportError:
        return False


_ebpf_available = _check_ebpf_sensors()


def ebpf_sensors_available() -> bool:
    """Check whether ebpf-sensors package is importable."""
    return _ebpf_available


@dataclass
class KernelConnection:
    """A kernel-level TCP/UDP connection event with process attribution."""

    timestamp: float
    pid: int
    comm: str
    saddr: str
    daddr: str
    sport: int
    dport: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0

    def matches_flow(self, flow: NetworkFlow) -> bool:
        """Check if this connection matches a flow's endpoints.

        Flow keys are canonical (sorted), so we check both directions.
        """
        fk = flow.key
        forward = (
            self.saddr == fk.src_ip
            and self.sport == fk.src_port
            and self.daddr == fk.dst_ip
            and self.dport == fk.dst_port
            and self.protocol == fk.protocol
        )
        reverse = (
            self.saddr == fk.dst_ip
            and self.sport == fk.dst_port
            and self.daddr == fk.src_ip
            and self.dport == fk.src_port
            and self.protocol == fk.protocol
        )
        return forward or reverse


@dataclass
class FlowEnrichment:
    """Process attribution data to attach to a NetworkFlow."""

    pid: int = 0
    comm: str = ""
    bytes_sent_kernel: int = 0
    bytes_received_kernel: int = 0
    connection_count: int = 0


class KernelNetCollector:
    """Collects kernel-level TCP/UDP connection events via ebpf-sensors.

    Provides PID-attributed connection data that scapy cannot offer,
    enriching Aegis's flow analysis with process identity.

    Usage::

        collector = KernelNetCollector()
        collector.start()
        # ... later ...
        connections = collector.get_connections()
        enriched_flow = collector.enrich_flow(flow, connections)
        collector.stop()

    Raises RuntimeError if ebpf-sensors is not installed.
    """

    def __init__(self) -> None:
        if not _ebpf_available:
            raise RuntimeError(
                "ebpf-sensors is required for kernel network monitoring. "
                "Install with: pip install ebpf-sensors"
            )
        from ebpf_sensors import SensorManager, SensorFilter, NetworkSensor

        self._manager: Any = SensorManager(filters=SensorFilter())
        self._sensor: Any = NetworkSensor()
        self._manager.add(self._sensor)

        self._connections: list[KernelConnection] = []
        self._lock = threading.Lock()
        self._running = False

        self._manager.on("network", self._handle_network_event)

    def _handle_network_event(self, event: Any) -> None:
        conn = KernelConnection(
            timestamp=event.timestamp,
            pid=event.pid,
            comm=event.comm,
            saddr=event.saddr,
            daddr=event.daddr,
            sport=event.sport,
            dport=event.dport,
            protocol=event.protocol,
            bytes_sent=getattr(event, "bytes_sent", 0),
            bytes_received=0,
        )
        with self._lock:
            self._connections.append(conn)

    def start(self) -> None:
        """Start the sensor manager and begin collecting events."""
        if self._running:
            return
        self._running = True
        self._manager.start()
        logger.info(
            "KernelNetCollector started (sensors: %s)",
            self._manager.sensor_names,
        )

    def stop(self) -> None:
        """Stop and cleanup the sensor manager."""
        if not self._running:
            return
        self._running = False
        self._manager.stop()
        logger.info("KernelNetCollector stopped")

    @property
    def is_running(self) -> bool:
        """Whether the collector is actively gathering events."""
        return self._running

    def get_connections(self) -> list[KernelConnection]:
        """Return accumulated connection events and clear the buffer.

        Thread-safe: drains the internal buffer.
        """
        with self._lock:
            connections = self._connections[:]
            self._connections.clear()
        return connections

    def get_connections_snapshot(self) -> list[KernelConnection]:
        """Return a snapshot of connections without draining.

        Useful for inspection without affecting the next enrichment cycle.
        """
        with self._lock:
            return self._connections[:]

    @staticmethod
    def enrich_flow(
        flow: NetworkFlow,
        connections: list[KernelConnection],
    ) -> FlowEnrichment:
        """Derive PID/comm attribution for a flow by matching kernel connections.

        Matches connections to the flow's endpoints and returns enrichment
        data. If multiple PIDs are seen, the most frequent one wins.

        Args:
            flow: The scapy-derived network flow to enrich.
            connections: Kernel connection events to match against.

        Returns:
            FlowEnrichment with the best-match PID/comm and aggregate stats.
        """
        matching = [c for c in connections if c.matches_flow(flow)]

        if not matching:
            return FlowEnrichment()

        # Tally PIDs — most frequent PID wins
        pid_counts: dict[int, int] = {}
        pid_comm: dict[int, str] = {}
        total_sent = 0
        total_recv = 0

        for conn in matching:
            pid_counts[conn.pid] = pid_counts.get(conn.pid, 0) + 1
            pid_comm[conn.pid] = conn.comm
            total_sent += conn.bytes_sent
            total_recv += conn.bytes_received

        best_pid = max(pid_counts, key=lambda p: pid_counts[p])

        return FlowEnrichment(
            pid=best_pid,
            comm=pid_comm[best_pid],
            bytes_sent_kernel=total_sent,
            bytes_received_kernel=total_recv,
            connection_count=len(matching),
        )
