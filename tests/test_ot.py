"""Industrial protocol parsing and the OT detector (Phase 7)."""
import struct

from scapy.all import IP, TCP, UDP, Ether, Raw

from capture import afpacket
from detection.ot import OTDetector, parse_bacnet, parse_dnp3, parse_modbus, parse_opcua, parse_ot
from detection.pipeline import DetectionPipeline

T0 = 1_800_000_000.0
DAY = 86400
PLC, HMI, LAPTOP = '192.168.10.5', '192.168.10.20', '192.168.10.77'


def modbus(fc, a=0, b=10, unit=1, tid=1):
    return struct.pack('>HHHBBHH', tid, 0, 6, unit, fc, a, b)


def dnp3(fc, master=True):
    ctrl = 0xC4 if master else 0x44
    return b'\x05\x64\x08' + bytes([ctrl]) + struct.pack('<HH', 4, 3) + b'\x00\x00' + bytes([0xC0, 0xC0, fc]) + b'\x00\x00'


def bacnet_confirmed(service):
    return b'\x81\x0a\x00\x0d\x01\x04' + bytes([0x00, 0x05, 0x01, service]) + b'\x0c\x02\x00'


WHO_IS = b'\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08'      # global broadcast: DNET, DLEN 0, hop count


def opcua_msg(request_id):
    return b'MSGF' + struct.pack('<I', 40) + b'\x01\x00\x00\x00' * 4 + b'\x01\x00' + struct.pack('<H', request_id) + b'\x00' * 8


# ---------- parsers ----------

def test_modbus_functions_writes_and_restart():
    assert parse_modbus(modbus(3)) == [{'protocol': 'modbus', 'code': 3, 'function': 'read holding registers',
                                        'write': False, 'stop': None, 'unit': 1}]
    assert parse_modbus(modbus(16))[0]['write'] is True
    restart = parse_modbus(modbus(8, 1, 0))[0]
    assert restart['stop'] == 'restart' and 'restart communications' in restart['function']
    assert parse_modbus(modbus(8, 4, 0))[0]['stop'] == 'listen-only'
    assert [m['code'] for m in parse_modbus(modbus(3) + modbus(6, tid=2))] == [3, 6]   # two ADUs in one segment
    assert parse_modbus(b'\x00\x01\x00\x07\x00\x06\x01\x03\x00\x00\x00\x0a') == []      # protocol id must be 0
    assert parse_modbus(struct.pack('>HHHBBB', 1, 0, 3, 1, 0x83, 2)) == []              # exception response


def test_dnp3_master_requests_only():
    m = parse_dnp3(dnp3(5))[0]
    assert m['function'] == 'direct operate' and m['write'] and m['unit'] == 4
    assert parse_dnp3(dnp3(13))[0]['stop'] == 'restart'
    assert parse_dnp3(dnp3(18))[0]['stop'] == 'stop'
    assert parse_dnp3(dnp3(1))[0]['write'] is False
    assert parse_dnp3(dnp3(0x81, master=False)) == []
    assert parse_dnp3(b'\x05\x65' + b'\x00' * 14) == []


def test_bacnet_services_and_network_headers():
    assert parse_bacnet(bacnet_confirmed(15))[0]['function'] == 'write property'
    reinit = parse_bacnet(bacnet_confirmed(20))[0]
    assert reinit['stop'] == 'restart' and reinit['write']
    assert parse_bacnet(bacnet_confirmed(12))[0]['write'] is False
    assert parse_bacnet(WHO_IS)[0]['function'] == 'who-is'
    assert parse_bacnet(b'\x81\x0a\x00\x07\x01\x80\x00') == []                      # network-layer message
    assert parse_bacnet(b'\x81\x0a\x00\x04') == []


def test_opcua_services_when_readable():
    assert parse_opcua(opcua_msg(673))[0]['function'] == 'write'
    assert parse_opcua(opcua_msg(631))[0]['write'] is False
    assert parse_opcua(opcua_msg(9999))[0]['function'] == 'message'                  # encrypted or unnamed
    assert parse_opcua(b'HELF' + b'\x00' * 28)[0]['function'] == 'hello'
    assert parse_opcua(b'GET / HTTP/1.1\r\n') == []


def test_parse_ot_selects_by_port_and_tolerates_junk():
    assert parse_ot('TCP', 502, modbus(3))[0] == 'modbus'
    assert parse_ot('UDP', 47808, WHO_IS)[0] == 'bacnet'
    assert parse_ot('TCP', 80, modbus(3)) == (None, [])
    assert parse_ot('UDP', 502, modbus(3)) == (None, [])
    assert parse_ot('TCP', 20000, b'\x05\x64\x08\xc4') == ('dnp3', [])


# ---------- detector ----------

def learned_detector():
    d = OTDetector(learning=7 * DAY)
    assert d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(3)), ts=T0) == []
    assert d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(6)), ts=T0 + 60) == []
    return d


def test_new_master_and_new_write_after_learning():
    d = learned_detector()
    later = T0 + 8 * DAY
    assert d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(3)), ts=later) == []
    assert d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(4)), ts=later) == []       # new read: fine
    [f] = d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(16)), ts=later + 1)
    assert f.kind == 'ot_new_write' and f.technique == 'T0855' and f.details['function'] == 'write multiple registers'
    [f] = d.observe(LAPTOP, PLC, 'modbus', parse_modbus(modbus(3)), ts=later + 2)
    assert f.kind == 'ot_new_master' and f.details['known_masters'] == [HMI]
    assert d.observe(LAPTOP, PLC, 'modbus', parse_modbus(modbus(3)), ts=later + 3) == []   # now known


def test_nothing_new_is_reported_while_learning():
    d = learned_detector()
    assert d.observe(LAPTOP, PLC, 'modbus', parse_modbus(modbus(16)), ts=T0 + DAY) == []


def test_restart_and_stop_are_always_reported():
    d = OTDetector()
    [f] = d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(8, 1, 0)), ts=T0)
    assert f.kind == 'ot_device_stop' and f.technique == 'T0816' and f.severity == 85
    [f] = d.observe(HMI, '192.168.10.6', 'dnp3', parse_dnp3(dnp3(18)), ts=T0)
    assert f.technique == 'T0814'
    assert d.observe(HMI, PLC, 'modbus', parse_modbus(modbus(8, 1, 0)), ts=T0 + 60) == []   # cooldown


def test_ot_across_the_internet_edge():
    [f] = OTDetector().observe('93.184.216.34', PLC, 'modbus', parse_modbus(modbus(3)), ts=T0)
    assert f.kind == 'ot_external' and f.technique == 'T0883'


def test_modbus_unit_id_sweep():
    d = OTDetector()
    found = [f for u in range(1, 30) for f in d.observe(LAPTOP, PLC, 'modbus', parse_modbus(modbus(43, unit=u)), ts=T0 + u)]
    assert [f.kind for f in found] == ['ot_scan'] and found[0].details['units'] == 16


def test_asset_inventory():
    d = learned_detector()
    [asset] = d.assets()
    assert asset['ip'] == PLC and asset['protocol'] == 'modbus'
    assert asset['masters'] == [{'ip': HMI, 'functions': ['read holding registers', 'write single register'],
                                 'last_seen': T0 + 60}]


# ---------- capture and pipeline ----------

def test_ot_requests_take_the_inspection_path():
    E = dict(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
    tcp = bytes(Ether(**E) / IP(src=HMI, dst=PLC) / TCP(sport=40000, dport=502) / Raw(modbus(3)))
    assert afpacket.parse(tcp)[6] is True
    udp = bytes(Ether(**E) / IP(src=HMI, dst='192.168.10.255') / UDP(sport=47808, dport=47808) / Raw(WHO_IS))
    assert afpacket.parse(udp)[6] is True
    web = bytes(Ether(**E) / IP(src=HMI, dst=PLC) / TCP(sport=40000, dport=8080) / Raw(b'GET /'))
    assert afpacket.parse(web)[6] is False


def test_pipeline_fuses_ot_findings():
    pipe = DetectionPipeline(models=False, clock=lambda: T0)
    protocol, messages, findings = pipe.observe_ot(HMI, PLC, 'TCP', 502, modbus(8, 1, 0), ts=T0)
    assert protocol == 'modbus' and messages[0]['stop'] == 'restart' and [f.kind for f in findings] == ['ot_device_stop']
    fused = pipe.fusion.fuse(HMI, 0, 0, 'TCP', None, now=T0 + 1)
    assert fused['attack_type'] == 'ot_device_stop'
    assert pipe.observe_ot(HMI, PLC, 'TCP', 443, modbus(3)) == (None, [], [])
