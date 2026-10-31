"""Fast packet capture: AF_PACKET raw socket + struct header parsing (Phase 6).

scapy parses ~5,000 packets/s on a Raspberry Pi 5; parsing the Ethernet,
IPv4/IPv6 and TCP/UDP headers directly is two orders of magnitude faster.
Only packets that need deep inspection go through scapy:
ARP and DHCP (device identity), DNS (tunnelling/DGA) and TLS handshakes
(JA3/JA4) and requests to industrial protocol ports (Modbus, DNP3, BACnet,
OPC UA). Everything else updates the flow table directly.

Selected with SENTINEL_CAPTURE=auto (default: AF_PACKET when permitted),
afpacket or scapy.
"""
import socket
import struct

ETH_P_ALL = 0x0003
SO_RCVBUF_BYTES = 8 * 1024 * 1024
SLOW_UDP_PORTS = frozenset({53, 67, 68, 5353, 20000, 47808})
SLOW_TCP_PORTS = frozenset({502, 4840, 20000})         # OT protocols (detection.ot)
_IP6_EXT = frozenset({0, 43, 44, 50, 51, 60})   # extension headers the fast path does not walk


def parse(frame):
    """(src, dst, sport, dport, proto, size, slow) from an Ethernet frame, or None for non-IP.

    slow=True means the packet also needs scapy (DNS, DHCP, TLS handshake, ARP, OT requests).
    """
    if len(frame) < 14:
        return None
    off = 12
    ethertype = struct.unpack_from('!H', frame, off)[0]
    off += 2
    while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:    # VLAN tags
        ethertype = struct.unpack_from('!H', frame, off + 2)[0]
        off += 4
    if ethertype == 0x0806:
        return ('', '', 0, 0, 'ARP', len(frame), True)
    if ethertype == 0x0800:
        if len(frame) < off + 20:
            return None
        ihl = (frame[off] & 0x0F) * 4
        proto = frame[off + 9]
        src = socket.inet_ntoa(frame[off + 12:off + 16])
        dst = socket.inet_ntoa(frame[off + 16:off + 20])
        l4 = off + ihl
        frag = struct.unpack_from('!H', frame, off + 6)[0] & 0x1FFF
        if frag:                                   # later fragments carry no ports
            return (src, dst, 0, 0, 'OTHER', len(frame), False)
    elif ethertype == 0x86DD:
        if len(frame) < off + 40:
            return None
        proto = frame[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, frame[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24:off + 40])
        l4 = off + 40
        if proto in _IP6_EXT:
            return (src, dst, 0, 0, 'OTHER', len(frame), True)
    else:
        return None
    if proto == 6 and len(frame) >= l4 + 14:
        sport, dport = struct.unpack_from('!HH', frame, l4)
        data_off = (frame[l4 + 12] >> 4) * 4
        payload = l4 + data_off
        slow = len(frame) > payload and (frame[payload] == 0x16      # TLS handshake record
                                         or dport in SLOW_TCP_PORTS)
        return (src, dst, sport, dport, 'TCP', len(frame), slow)
    if proto == 17 and len(frame) >= l4 + 8:
        sport, dport = struct.unpack_from('!HH', frame, l4)
        return (src, dst, sport, dport, 'UDP', len(frame), sport in SLOW_UDP_PORTS or dport in SLOW_UDP_PORTS)
    return (src, dst, 0, 0, 'OTHER', len(frame), False)


def open_socket(interface=None):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
    if interface:
        sock.bind((interface, 0))
    return sock


def available():
    try:
        open_socket().close()
        return True
    except (OSError, AttributeError):
        return False


def run(interface, on_fast, on_slow, stop=None):
    """Capture until stop() returns True. on_fast(src, dst, sport, dport, proto, size); on_slow(frame_bytes)."""
    sock = open_socket(interface)
    buf = bytearray(65535)
    view = memoryview(buf)
    try:
        while not (stop and stop()):
            n = sock.recv_into(buf)
            frame = bytes(view[:n])
            parsed = parse(frame)
            if parsed is None:
                continue
            src, dst, sport, dport, proto, size, slow = parsed
            if slow:
                on_slow(frame)          # scapy path also does the flow accounting
            elif proto != 'ARP':
                on_fast(src, dst, sport, dport, proto, size)
    finally:
        sock.close()
