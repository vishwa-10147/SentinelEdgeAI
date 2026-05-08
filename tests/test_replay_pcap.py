import tempfile
from pathlib import Path

import pytest


try:
    from scapy.all import IP, TCP, Ether, wrpcap
except Exception:  # pragma: no cover - scapy optional in some test envs
    pytest.skip("scapy not installed; skipping pcap replay tests", allow_module_level=True)

from scripts.replay_pcap import replay_pcap


def make_small_pcap(path: Path, count: int = 10):
    packets = []
    for i in range(count):
        pkt = Ether() / IP(src=f"10.0.0.{i+1}", dst="198.51.100.1") / TCP(sport=1024 + i, dport=80)
        packets.append(pkt)
    wrpcap(str(path), packets)


def test_replay_pcap_small(tmp_path):
    pcap = tmp_path / "sample.pcap"
    make_small_pcap(pcap, count=20)

    result = replay_pcap(pcap)
    assert result["packets"] == 20
    assert result["flows"] >= 1
    assert result["elapsed_seconds"] >= 0
