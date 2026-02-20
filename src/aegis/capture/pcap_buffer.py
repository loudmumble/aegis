"""PCAP ring buffer for live capture with anomaly preservation.

Records live traffic to rotating PCAP segments via tcpdump subprocess.
When anomalies are detected, segments are preserved (copied to a preserved/
directory) and relevant flows are added to a watchlist for continued monitoring.
"""

import logging
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class WatchEntry:
    """A flow tuple being watched for continued anomaly activity."""

    dst_ip: str
    dst_port: int
    reason: str
    added_at: float
    ttl_seconds: float

    @property
    def is_expired(self) -> bool:
        return time.time() - self.added_at > self.ttl_seconds


class AnomalyWatchlist:
    """Tracks flows flagged by anomaly detection for continued monitoring."""

    def __init__(self) -> None:
        self._entries: list[WatchEntry] = []
        self._lock = threading.Lock()

    def add_flow(
        self,
        dst_ip: str,
        dst_port: int,
        reason: str,
        ttl_seconds: float = 3600.0,
    ) -> None:
        with self._lock:
            for entry in self._entries:
                if entry.dst_ip == dst_ip and entry.dst_port == dst_port:
                    entry.added_at = time.time()
                    entry.ttl_seconds = ttl_seconds
                    entry.reason = reason
                    return
            self._entries.append(
                WatchEntry(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    reason=reason,
                    added_at=time.time(),
                    ttl_seconds=ttl_seconds,
                )
            )

    def is_watched(self, dst_ip: str, dst_port: int) -> bool:
        with self._lock:
            return any(
                e.dst_ip == dst_ip and e.dst_port == dst_port and not e.is_expired
                for e in self._entries
            )

    def expire(self) -> int:
        """Remove expired entries. Returns number removed."""
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if not e.is_expired]
            return before - len(self._entries)

    @property
    def entries(self) -> list[WatchEntry]:
        with self._lock:
            return list(self._entries)


class AnomalyPinner:
    """Pins PCAP segments when anomalies are detected."""

    def __init__(self, pcap_dir: Path, preserved_dir: Path) -> None:
        self._pcap_dir = pcap_dir
        self._preserved_dir = preserved_dir
        self._preserved_dir.mkdir(parents=True, exist_ok=True)
        self._pinned: list[Path] = []
        self._lock = threading.Lock()

    def pin_current(
        self,
        reason: str,
        current_segment: Path | None,
        previous_segment: Path | None = None,
    ) -> list[Path]:
        """Pin current and previous segments by copying to preserved_dir."""
        pinned: list[Path] = []
        safe_reason = reason.replace("/", "_").replace(" ", "_")[:50]

        for seg in (previous_segment, current_segment):
            if seg is None or not seg.exists():
                continue
            dest_name = f"preserved_{safe_reason}_{seg.name}"
            dest = self._preserved_dir / dest_name
            if dest.exists():
                continue
            try:
                shutil.copy2(seg, dest)
                pinned.append(dest)
                logger.info("Pinned segment: %s -> %s", seg.name, dest.name)
            except OSError:
                logger.warning("Failed to pin segment: %s", seg, exc_info=True)

        with self._lock:
            self._pinned.extend(pinned)
        return pinned

    @property
    def pinned_segments(self) -> list[Path]:
        with self._lock:
            return list(self._pinned)


class PcapRingBuffer:
    """Rotating PCAP ring buffer using tcpdump subprocess.

    Writes live traffic to rotating segment files. Old segments are deleted
    when max_segments is exceeded, unless they have been pinned by the
    AnomalyPinner.
    """

    def __init__(
        self,
        pcap_dir: Path,
        segment_duration: float = 300.0,
        max_segments: int = 6,
    ) -> None:
        self.pcap_dir = pcap_dir
        self.segment_duration = segment_duration
        self.max_segments = max_segments
        self.preserved_dir = pcap_dir / "preserved"

        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.preserved_dir.mkdir(parents=True, exist_ok=True)

        self.pinner = AnomalyPinner(self.pcap_dir, self.preserved_dir)
        self.watchlist = AnomalyWatchlist()

        self._process: subprocess.Popen[bytes] | None = None
        self._rotation_thread: threading.Thread | None = None
        self._running = False
        self._seq = 0
        self._segments: list[Path] = []
        self._current_segment: Path | None = None
        self._previous_segment: Path | None = None
        self._interface: str = "any"
        self._bpf_filter: str = "tcp"
        self._lock = threading.Lock()
        self._segments_written = 0
        self._segments_preserved = 0

    def _make_segment_path(self) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        name = f"aegis_{ts}_{self._seq}.pcap"
        self._seq += 1
        return self.pcap_dir / name

    def _start_tcpdump(self, segment_path: Path) -> subprocess.Popen[bytes]:
        cmd = [
            "tcpdump",
            "-i",
            self._interface,
            "-w",
            str(segment_path),
            "-s",
            "0",
        ]
        if self._bpf_filter:
            cmd.append(self._bpf_filter)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc

    def _rotate(self) -> None:
        with self._lock:
            old_process = self._process
            self._previous_segment = self._current_segment

            new_segment = self._make_segment_path()
            self._current_segment = new_segment
            self._segments.append(new_segment)
            self._segments_written += 1

            try:
                self._process = self._start_tcpdump(new_segment)
            except FileNotFoundError:
                logger.error("tcpdump not found; PCAP ring buffer disabled")
                self._running = False
                return

        if old_process is not None:
            old_process.terminate()
            try:
                old_process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                old_process.kill()

        self._cleanup_old_segments()

    def _cleanup_old_segments(self) -> None:
        with self._lock:
            preserved_names = {p.name for p in self.pinner.pinned_segments}
            while len(self._segments) > self.max_segments:
                oldest = self._segments[0]
                is_pinned = any(oldest.name in pname for pname in preserved_names)
                if oldest == self._current_segment:
                    break
                self._segments.pop(0)
                if not is_pinned and oldest.exists():
                    try:
                        oldest.unlink()
                        logger.debug("Deleted old segment: %s", oldest.name)
                    except OSError:
                        pass

    def _rotation_loop(self) -> None:
        while self._running:
            time.sleep(self.segment_duration)
            if self._running:
                self._rotate()

    def start(self, interface: str, bpf_filter: str = "tcp") -> None:
        """Start the PCAP ring buffer."""
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._running = True

        first_segment = self._make_segment_path()
        self._current_segment = first_segment
        self._segments.append(first_segment)
        self._segments_written += 1

        try:
            self._process = self._start_tcpdump(first_segment)
        except FileNotFoundError:
            logger.error("tcpdump not found; PCAP ring buffer will not record")
            self._running = False
            return

        self._rotation_thread = threading.Thread(
            target=self._rotation_loop, daemon=True, name="aegis-pcap-rotation"
        )
        self._rotation_thread.start()
        logger.info(
            "PCAP ring buffer started: dir=%s duration=%.0fs max_segments=%d",
            self.pcap_dir,
            self.segment_duration,
            self.max_segments,
        )

    def stop(self) -> None:
        """Stop the PCAP ring buffer and terminate tcpdump."""
        self._running = False
        if self._rotation_thread:
            self._rotation_thread.join(timeout=2.0)
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    @property
    def current_segment_path(self) -> Path | None:
        with self._lock:
            return self._current_segment

    @property
    def segments_written(self) -> int:
        return self._segments_written

    @property
    def segments_preserved(self) -> int:
        return len(self.pinner.pinned_segments)

    def pin_current(self, reason: str) -> list[Path]:
        """Pin the current and previous segments."""
        with self._lock:
            current = self._current_segment
            previous = self._previous_segment
        pinned = self.pinner.pin_current(reason, current, previous)
        self._segments_preserved += len(pinned)
        return pinned
