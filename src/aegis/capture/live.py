"""Live network packet capture using scapy sniff.

Provides continuous monitoring by capturing packets from a network interface,
grouping them into flows via FlowTracker, and periodically running cadence
analysis to detect beaconing and agent patterns in real-time.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .flows import FlowTracker, NetworkFlow
from .kernel_net import FlowEnrichment, KernelNetCollector
from ..config import CaptureConfig, CadenceConfig
from ..detection.cadence import CadenceAnalyzer, CadenceResult
from ..detection.rules import RuleEngine, RuleMatch

if TYPE_CHECKING:
    from .pcap_buffer import PcapRingBuffer

logger = logging.getLogger(__name__)


@dataclass
class MonitorStats:
    """Running statistics for live monitoring."""

    packets_captured: int = 0
    flows_analyzed: int = 0
    alerts_generated: int = 0
    analysis_cycles: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def packets_per_second(self) -> float:
        uptime = self.uptime_seconds
        return self.packets_captured / uptime if uptime > 0 else 0.0


@dataclass
class AnalysisCycleResult:
    """Result of a single analysis cycle."""

    cadence_results: list[CadenceResult]
    rule_matches: list[RuleMatch]
    flows_analyzed: int
    cycle_number: int
    timestamp: float = field(default_factory=time.time)


class LiveCapture:
    """Live network packet capture with continuous cadence analysis.

    Usage:
        capture = LiveCapture(capture_config, cadence_config)
        capture.start(on_result=my_callback)  # Blocks until stop() or KeyboardInterrupt
    """

    def __init__(
        self,
        capture_config: CaptureConfig,
        cadence_config: CadenceConfig,
        rules_dir: Path | None = None,
        analysis_interval: float = 10.0,
        pcap_buffer: "PcapRingBuffer | None" = None,
        kernel_net_collector: KernelNetCollector | None = None,
    ):
        self.capture_config = capture_config
        self.cadence_config = cadence_config
        self.rules_dir = rules_dir
        self.analysis_interval = analysis_interval
        self.pcap_buffer = pcap_buffer
        self.kernel_net_collector = kernel_net_collector

        self.tracker = FlowTracker(flow_timeout=capture_config.flow_timeout)
        self.cadence_analyzer = CadenceAnalyzer(cadence_config)
        self.rule_engine = RuleEngine(rules_dir=rules_dir, builtin_enabled=True)

        self.stats = MonitorStats()
        self._running = False
        self._analysis_thread: threading.Thread | None = None
        self._on_result: Callable[[AnalysisCycleResult], None] | None = None
        self._analyzed_flow_keys: set[str] = set()
        self._watchlist_triggered = False
        # Enrichment data from kernel-level monitoring, keyed by flow key string
        self.flow_enrichments: dict[str, FlowEnrichment] = {}

    def _packet_callback(self, pkt) -> None:
        """Process each captured packet."""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            return

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        size = len(pkt)
        timestamp = float(pkt.time)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = str(tcp.flags)
            payload_size = len(tcp.payload) if tcp.payload else 0
            self.tracker.process_packet(
                timestamp=timestamp,
                src_ip=src_ip,
                src_port=tcp.sport,
                dst_ip=dst_ip,
                dst_port=tcp.dport,
                protocol="tcp",
                size=size,
                flags=flags,
                payload_size=payload_size,
            )
            self.stats.packets_captured += 1
            if self.pcap_buffer and self.pcap_buffer.watchlist.is_watched(
                dst_ip, tcp.dport
            ):
                self._watchlist_triggered = True
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            payload_size = len(udp.payload) if udp.payload else 0
            self.tracker.process_packet(
                timestamp=timestamp,
                src_ip=src_ip,
                src_port=udp.sport,
                dst_ip=dst_ip,
                dst_port=udp.dport,
                protocol="udp",
                size=size,
                payload_size=payload_size,
            )
            self.stats.packets_captured += 1
            if self.pcap_buffer and self.pcap_buffer.watchlist.is_watched(
                dst_ip, udp.dport
            ):
                self._watchlist_triggered = True

    def _analysis_loop(self) -> None:
        """Periodic analysis of accumulated flows."""
        while self._running:
            time.sleep(self.analysis_interval)
            if not self._running:
                break
            self._run_analysis_cycle()

    def _run_analysis_cycle(self) -> None:
        """Run one analysis cycle: expire flows, analyze, evaluate rules."""
        self.stats.analysis_cycles += 1

        self.tracker.expire_flows()

        analyzable = self.tracker.get_analyzable_flows(
            min_packets=self.cadence_config.min_packets_for_analysis
        )
        completed_new = [
            f
            for f in self.tracker.completed_flows
            if self._flow_key_str(f) not in self._analyzed_flow_keys
            and f.packet_count >= self.cadence_config.min_packets_for_analysis
        ]
        all_flows = analyzable + completed_new

        if not all_flows:
            return

        if self.kernel_net_collector and self.kernel_net_collector.is_running:
            kernel_connections = self.kernel_net_collector.get_connections()
            if kernel_connections:
                for flow in all_flows:
                    enrichment = KernelNetCollector.enrich_flow(
                        flow, kernel_connections
                    )
                    if enrichment.pid > 0:
                        fk = self._flow_key_str(flow)
                        self.flow_enrichments[fk] = enrichment
                        logger.debug(
                            "Enriched %s → pid=%d comm=%s",
                            fk,
                            enrichment.pid,
                            enrichment.comm,
                        )

        for f in all_flows:
            self._analyzed_flow_keys.add(self._flow_key_str(f))

        # Cadence analysis
        cadence_results = self.cadence_analyzer.analyze_flows(all_flows)
        if not cadence_results:
            return

        self.stats.flows_analyzed += len(cadence_results)

        # Rule evaluation
        rule_matches = self.rule_engine.evaluate_all(cadence_results, all_flows)
        self.stats.alerts_generated += len(rule_matches)

        if self.pcap_buffer:
            for rm in rule_matches:
                self.pcap_buffer.pin_current(reason=rm.rule.id)
                dst_ip, dst_port = self._parse_dst_from_flow_key(rm.flow_key)
                if dst_ip and dst_port:
                    self.pcap_buffer.watchlist.add_flow(dst_ip, dst_port, rm.rule.id)

            if self._watchlist_triggered:
                self.pcap_buffer.pin_current(reason="watchlist_activity")
                self._watchlist_triggered = False

            self.pcap_buffer.watchlist.expire()

        # Dispatch result
        result = AnalysisCycleResult(
            cadence_results=cadence_results,
            rule_matches=rule_matches,
            flows_analyzed=len(cadence_results),
            cycle_number=self.stats.analysis_cycles,
        )

        if self._on_result:
            try:
                self._on_result(result)
            except Exception:
                logger.debug("Result callback failed", exc_info=True)

    @staticmethod
    def _flow_key_str(flow: NetworkFlow) -> str:
        """Generate a string key for flow deduplication."""
        k = flow.key
        return f"{k.src_ip}:{k.src_port}-{k.dst_ip}:{k.dst_port}-{k.protocol}"

    @staticmethod
    def _parse_dst_from_flow_key(flow_key: str) -> tuple[str, int]:
        try:
            parts = flow_key.replace("→", "->").split("->")
            if len(parts) < 2:
                parts = flow_key.split("-")
                if len(parts) >= 2:
                    dst_part = parts[1].strip().split(":")[0:2]
                    return dst_part[0], int(dst_part[1])
                return "", 0
            dst_part = parts[1].strip().split("(")[0].strip()
            ip_port = dst_part.split(":")
            return ip_port[0].strip(), int(ip_port[1].strip())
        except (IndexError, ValueError):
            return "", 0

    def start(
        self,
        on_result: Callable[[AnalysisCycleResult], None] | None = None,
    ) -> None:
        """Start live capture. Blocks until stop() is called or KeyboardInterrupt.

        Args:
            on_result: Callback invoked after each analysis cycle with results.
        """
        try:
            from scapy.all import sniff
        except ImportError:
            raise RuntimeError(
                "scapy is required for live capture. Install with: pip install scapy"
            )

        self._on_result = on_result
        self._running = True

        if self.kernel_net_collector:
            try:
                self.kernel_net_collector.start()
                logger.info("Kernel network collector active")
            except Exception as exc:
                logger.warning("Failed to start kernel net collector: %s", exc)

        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, daemon=True, name="aegis-analysis"
        )
        self._analysis_thread.start()

        logger.info(
            "Starting live capture on interface=%s filter='%s' interval=%.1fs",
            self.capture_config.interface,
            self.capture_config.bpf_filter,
            self.analysis_interval,
        )

        try:
            sniff(
                iface=self.capture_config.interface
                if self.capture_config.interface != "any"
                else None,
                filter=self.capture_config.bpf_filter,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            if self._analysis_thread:
                self._analysis_thread.join(timeout=2.0)
            if self.kernel_net_collector:
                self.kernel_net_collector.stop()
            self._run_analysis_cycle()

    def stop(self) -> None:
        """Signal the capture to stop."""
        self._running = False

    def save_pcap(self, output_path: Path) -> Path | None:
        """Save captured packets to a PCAP file for later analysis."""
        # Note: We don't store packets (store=False for memory efficiency).
        # If PCAP saving is needed, the user should run tcpdump in parallel.
        logger.warning(
            "PCAP saving requires external tcpdump -- live capture uses store=False"
        )
        return None
