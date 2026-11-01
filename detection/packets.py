"""Per-packet dispatch to the protocol detectors, shared by the live engine (capture.sniffer) and the
offline pcap evaluator (evaluation.pcap), so both run exactly the same code.

dispatch() feeds DNS answers, TLS handshakes (client and server), plain-HTTP requests, SMB / DCE-RPC /
Kerberos / LDAP requests and industrial-protocol requests of one scapy packet to the pipeline and returns
the findings. `ts` is the packet time (None: the pipeline's clock).
"""
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from detection.http import is_http_request

LATERAL_TCP = (88, 135, 139, 445, 389, 3268)
SIZE_CAPPED = (139, 445, 389, 3268)          # bulk SMB data and sealed LDAP are not inspected
INSPECT_MAX = 1200


def dispatch(pipe, packet, ts=None):
    if IP not in packet:
        return []
    ip = packet[IP]
    if DNS in packet and packet[DNS].qr == 1 and packet[DNS].qd is not None:
        qname = packet[DNS].qd.qname
        qname = qname.decode('ascii', 'replace') if isinstance(qname, bytes) else str(qname)
        return pipe.observe_dns(ip.dst, qname, nxdomain=packet[DNS].rcode == 3, ts=ts)
    if TCP in packet and Raw in packet:
        payload = bytes(packet[Raw].load)
        tcp = packet[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if payload[:1] == b'\x16' and payload[5:6] == b'\x02' or key in pipe.server_handshakes.pending:
            return pipe.observe_tls_server(*key, payload, ts=ts)[1]       # ServerHello, certificates
        if payload[:1] == b'\x16':
            return pipe.observe_tls(ip.src, ip.dst, payload, ts=ts)[1]
        if is_http_request(payload):
            return pipe.observe_http(ip.src, ip.dst, payload, ts=ts)[1]
        if tcp.dport in LATERAL_TCP:
            if tcp.dport not in SIZE_CAPPED or len(payload) <= INSPECT_MAX:
                return pipe.observe_lateral(ip.src, ip.dst, 'TCP', tcp.dport, payload, ts=ts)[2]
            return []
        return pipe.observe_ot(ip.src, ip.dst, 'TCP', tcp.dport, payload, ts=ts)[2]
    if UDP in packet and Raw in packet:
        udp = packet[UDP]
        if udp.dport in (88, 389):
            return pipe.observe_lateral(ip.src, ip.dst, 'UDP', udp.dport, bytes(packet[Raw].load), ts=ts)[2]
        return pipe.observe_ot(ip.src, ip.dst, 'UDP', udp.dport, bytes(packet[Raw].load), ts=ts)[2]
    return []
