from scapy.all import Ether, IP, TCP, UDP, wrpcap

from scripts.replay_pcap import replay_pcap


def test_replay_pcap_extracts_flows(tmp_path):
    pcap = tmp_path / "sample.pcap"
    csv_out = tmp_path / "flows.csv"
    packets = [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=12345, dport=443),
        Ether() / IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=443, dport=12345),
        Ether() / IP(src="192.0.2.11", dst="198.51.100.53") / UDP(sport=53000, dport=53),
    ]
    wrpcap(str(pcap), packets)

    result = replay_pcap(pcap, output_csv=csv_out)

    assert result["packets"] == 3
    assert result["flows"] == 2
    assert len(result["features"]) == 2
    assert csv_out.exists()
