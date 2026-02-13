"""PCAP file reader using scapy for offline analysis."""

from pathlib import Path

from .flows import FlowTracker, NetworkFlow


class PcapReader:
    """Read PCAP/PCAPNG files and extract flows."""

    def __init__(self, tracker: FlowTracker):
        self.tracker: FlowTracker = tracker

    def read_pcap(self, pcap_path: Path) -> list[NetworkFlow]:
        """Read a PCAP file and return extracted flows."""
        try:
            from scapy.all import rdpcap, TCP, UDP, IP
        except ImportError:
            raise RuntimeError(
                "scapy is required for PCAP reading. Install with: pip install scapy"
            )

        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        packets = rdpcap(str(pcap_path))

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

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

        # Expire all remaining flows
        if packets:
            last_time = float(packets[-1].time)
            self.tracker.expire_flows(last_time + self.tracker.flow_timeout + 1)

        all_flows = self.tracker.completed_flows + self.tracker.get_active_flows()
        return all_flows

    @staticmethod
    def generate_test_pcap(output_path: Path, pattern: str = "agent") -> Path:
        """Generate a synthetic PCAP for testing cadence detection.

        Patterns:
            'agent': Regular timing (LLM-like), small IAT variance
            'human': Irregular timing with think-time gaps
            'mixed': Human session that transitions to agent behavior
        """
        try:
            from scapy.all import wrpcap, Ether, IP, TCP, Raw
        except ImportError:
            raise RuntimeError("scapy required for PCAP generation")

        import random

        packets = []
        base_time = 1000000000.0  # Arbitrary epoch

        src_ip = "10.0.0.50"
        dst_ip = "192.168.1.100"
        src_port = 54321
        dst_port = 443

        if pattern == "agent":
            # LLM streaming response: very regular inter-token timing ~45ms ± 3ms
            t = base_time
            for i in range(200):
                # Forward: client request chunk
                if i % 20 == 0:
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=src_port, dport=dst_port, flags="PA")
                        / Raw(load=b"X" * random.randint(100, 300))
                    )
                    pkt.time = t
                    packets.append(pkt)
                    t += random.uniform(0.001, 0.005)

                # Reverse: streaming token response
                iat = random.gauss(0.045, 0.003)  # ~45ms very regular
                iat = max(iat, 0.010)
                t += iat
                pkt = (
                    Ether()
                    / IP(src=dst_ip, dst=src_ip)
                    / TCP(sport=dst_port, dport=src_port, flags="PA")
                    / Raw(load=b"T" * random.randint(20, 80))
                )
                pkt.time = t
                packets.append(pkt)

        elif pattern == "human":
            # Human SSH session: irregular timing, think pauses, varying command sizes
            t = base_time
            for i in range(100):
                # Human types a command (variable think time)
                think_time = random.expovariate(0.5)  # Mean 2s, exponential
                think_time = min(think_time, 15.0)
                t += think_time

                pkt = (
                    Ether()
                    / IP(src=src_ip, dst=dst_ip)
                    / TCP(sport=src_port, dport=dst_port, flags="PA")
                    / Raw(load=b"C" * random.randint(10, 200))
                )
                pkt.time = t
                packets.append(pkt)

                # Response: variable delay
                resp_delay = random.uniform(0.05, 2.0)
                t += resp_delay
                pkt = (
                    Ether()
                    / IP(src=dst_ip, dst=src_ip)
                    / TCP(sport=dst_port, dport=src_port, flags="PA")
                    / Raw(load=b"R" * random.randint(50, 5000))
                )
                pkt.time = t
                packets.append(pkt)

        elif pattern == "mixed":
            # Starts human, transitions to agent mid-session
            t = base_time

            # Phase 1: Human (50 exchanges)
            for _ in range(50):
                t += random.expovariate(0.5)
                pkt = (
                    Ether()
                    / IP(src=src_ip, dst=dst_ip)
                    / TCP(sport=src_port, dport=dst_port, flags="PA")
                    / Raw(load=b"H" * random.randint(10, 200))
                )
                pkt.time = t
                packets.append(pkt)

                t += random.uniform(0.05, 2.0)
                pkt = (
                    Ether()
                    / IP(src=dst_ip, dst=src_ip)
                    / TCP(sport=dst_port, dport=src_port, flags="PA")
                    / Raw(load=b"R" * random.randint(50, 1000))
                )
                pkt.time = t
                packets.append(pkt)

            # Phase 2: Agent takes over (150 tokens)
            for i in range(150):
                if i % 25 == 0:
                    pkt = (
                        Ether()
                        / IP(src=src_ip, dst=dst_ip)
                        / TCP(sport=src_port, dport=dst_port, flags="PA")
                        / Raw(load=b"A" * random.randint(200, 500))
                    )
                    pkt.time = t
                    packets.append(pkt)
                    t += random.uniform(0.001, 0.005)

                iat = random.gauss(0.045, 0.003)
                iat = max(iat, 0.010)
                t += iat
                pkt = (
                    Ether()
                    / IP(src=dst_ip, dst=src_ip)
                    / TCP(sport=dst_port, dport=src_port, flags="PA")
                    / Raw(load=b"T" * random.randint(20, 80))
                )
                pkt.time = t
                packets.append(pkt)
        else:
            raise ValueError(f"Unknown pattern: {pattern}. Use: agent, human, mixed")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), packets)
        return output_path
