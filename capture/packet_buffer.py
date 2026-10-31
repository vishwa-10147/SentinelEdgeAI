"""Forensic packet buffer (Phase 9).

Keeps a bounded ring buffer of raw packets per source IP. When an alert is
raised for a device, the buffered packets around the alert are written to a
PCAP file in data/pcaps/ and can be exported through the API and console.

PCAP files use the standard libpcap format so they can be opened in
Wireshark, tcpdump, etc.

    python -m capture.packet_buffer list          # list stored captures
    python -m capture.packet_buffer export <ip>   # write pending buffer to pcap
"""
import os
import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path

# PCAP constants
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
PCAP_NETWORK = 1  # LINKTYPE_ETHERNET

PCAP_HEADER = struct.pack(
    "<IHHiIII",
    PCAP_MAGIC,
    PCAP_VERSION_MAJOR,
    PCAP_VERSION_MINOR,
    PCAP_THISZONE,
    PCAP_SIGFIGS,
    PCAP_SNAPLEN,
    PCAP_NETWORK,
)

PCAP_PACKET_HEADER = struct.Struct("<IIII")


class PacketBuffer:
    """Thread-safe ring buffer of raw packets per source IP.

    Each source keeps at most MAX_PACKETS_PER_SOURCE packets. Older packets
    are dropped when the buffer is full. A global cap bounds total memory.
    """

    def __init__(self, max_packets_per_source=5000, max_total_packets=100000,
                 pcaps_dir=None):
        self.max_packets_per_source = max_packets_per_source
        self.max_total_packets = max_total_packets
        self.pcaps_dir = Path(pcaps_dir or os.path.join("data", "pcaps"))
        self.pcaps_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._buffers = {}        # src_ip -> deque of (timestamp, raw_bytes)
        self._total = 0           # total packets across all sources
        self._order = deque()     # (src_ip, sequence) for global eviction

    def add(self, src_ip, raw_bytes, ts=None):
        """Store one raw packet for a source."""
        if ts is None:
            ts = time.time()
        with self._lock:
            buf = self._buffers.get(src_ip)
            if buf is None:
                buf = deque(maxlen=self.max_packets_per_source)
                self._buffers[src_ip] = buf
            buf.append((ts, raw_bytes))
            self._total += 1
            self._order.append((src_ip, len(buf) - 1))
            # Global eviction: drop oldest packets across all sources
            while self._total > self.max_total_packets and self._order:
                old_src, _ = self._order.popleft()
                old_buf = self._buffers.get(old_src)
                if old_buf and len(old_buf) > 0:
                    old_buf.popleft()
                    self._total -= 1

    def snapshot(self, src_ip, before_seconds=30, after_seconds=30):
        """Return a copy of buffered packets for a source around now.

        Packets are kept in the ring buffer indefinitely (subject to eviction);
        this returns everything currently buffered for the source.
        """
        with self._lock:
            buf = self._buffers.get(src_ip)
            if not buf:
                return []
            return list(buf)

    def clear(self, src_ip=None):
        """Clear buffer for a source, or all sources if None."""
        with self._lock:
            if src_ip:
                buf = self._buffers.pop(src_ip, None)
                if buf:
                    self._total -= len(buf)
            else:
                self._buffers.clear()
                self._total = 0
                self._order.clear()


# Module-level singleton
_buffer = None


def get_buffer():
    global _buffer
    if _buffer is None:
        _buffer = PacketBuffer()
    return _buffer


def observe_packet(src_ip, raw_bytes, ts=None):
    """Called from the capture path for every packet."""
    get_buffer().add(src_ip, raw_bytes, ts)


def export_pcap(src_ip, path=None, before_seconds=30, after_seconds=30):
    """Write buffered packets for a source to a PCAP file.

    Returns the path of the written file, or None if no packets buffered.
    """
    buf = get_buffer().snapshot(src_ip, before_seconds, after_seconds)
    if not buf:
        return None

    get_buffer().pcaps_dir.mkdir(parents=True, exist_ok=True)
    if path is None:
        stamp = int(time.time())
        safe = src_ip.replace(":", "_").replace(".", "_")
        path = get_buffer().pcaps_dir / f"capture-{safe}-{stamp}.pcap"

    with open(path, "wb") as f:
        f.write(PCAP_HEADER)
        for ts, raw in buf:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(PCAP_PACKET_HEADER.pack(sec, usec, len(raw), len(raw)))
            f.write(raw)

    return str(path)


def list_pcaps():
    """List stored PCAP files, newest first."""
    d = get_buffer().pcaps_dir
    if not d.exists():
        return []
    files = sorted(d.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
    out = []
    for p in files:
        st = p.stat()
        out.append({
            "name": p.name,
            "path": str(p),
            "size": st.st_size,
            "modified": st.st_mtime,
        })
    return out
