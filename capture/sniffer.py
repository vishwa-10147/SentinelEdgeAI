from scapy.all import sniff, IP, TCP, UDP
from flow.flow_table import FlowTable


flow_table = FlowTable(idle_timeout=30)


def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        size = len(packet)

        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"

        else:
            protocol_name = "OTHER"

        flow_table.process_packet(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol_name,
            size
        )

        expired = flow_table.check_timeouts()
        for flow in expired:
            print(flow)


def start_sniffing(interface=None):
    sniff(prn=process_packet, iface=interface, store=False)
