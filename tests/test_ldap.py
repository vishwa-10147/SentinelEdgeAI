"""LDAP metadata and the Active Directory reconnaissance detectors (Phase 9, lateral movement)."""
from capture import afpacket
from core.incidents import checklist
from detection.lateral import LateralDetector, ldap_markers, parse_filter_text, parse_lateral, parse_ldap
from detection.pipeline import DetectionPipeline
from integrations.zeek import ZeekFeeder
from scapy.all import IP, TCP, UDP, Ether, Raw

T0 = 1_700_000_000.0
WEEK = 7 * 86400
WS, DC = '10.0.0.20', '10.0.0.2'
BASE = b'DC=corp,DC=example'


# ---------- a minimal BER encoder for building requests ----------

def tlv(tag, body):
    n = len(body)
    if n < 128:
        length = bytes([n])
    elif n < 256:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82]) + n.to_bytes(2, 'big')
    return bytes([tag]) + length + body


def AND(*f):
    return tlv(0xa0, b''.join(f))


def eq(attr, value):
    return tlv(0xa3, tlv(0x04, attr.encode()) + tlv(0x04, value.encode()))


def present(attr):
    return tlv(0x87, attr.encode())


def ext(attr, rule, value):
    return tlv(0xa9, tlv(0x81, rule.encode()) + tlv(0x82, attr.encode()) + tlv(0x83, value.encode()))


def search(flt, attrs=(), base=BASE, scope=2, msgid=1):
    body = (tlv(0x04, base) + tlv(0x0a, bytes([scope])) + tlv(0x0a, b'\x00') + tlv(0x02, b'\x00')
            + tlv(0x02, b'\x00') + tlv(0x01, b'\x00') + flt
            + tlv(0x30, b''.join(tlv(0x04, a.encode()) for a in attrs)))
    return tlv(0x30, tlv(0x02, bytes([msgid])) + tlv(0x63, body))


def bind_simple(dn=b'CN=svc-app,OU=Service,DC=corp,DC=example', password=b'Winter2026!'):
    return tlv(0x30, tlv(0x02, b'\x01') + tlv(0x60, tlv(0x02, b'\x03') + tlv(0x04, dn) + tlv(0x80, password)))


def bind_sasl(mech=b'GSS-SPNEGO'):
    return tlv(0x30, tlv(0x02, b'\x01') + tlv(0x60, tlv(0x02, b'\x03') + tlv(0x04, b'')
                                                + tlv(0xa3, tlv(0x04, mech) + tlv(0x04, b'\x60\x00'))))


KERBEROAST = search(AND(eq('samAccountType', '805306368'), present('servicePrincipalName')),
                    ['servicePrincipalName', 'sAMAccountName'])
ASREP = search(AND(eq('objectCategory', 'person'), ext('userAccountControl', '1.2.840.113556.1.4.803', '4194304')))
TRUSTS = search(eq('objectClass', 'trustedDomain'), ['trustPartner', 'trustDirection'])
LAPS = search(eq('objectCategory', 'computer'), ['ms-Mcs-AdmPwd', 'name'])
ADMINS = search(eq('adminCount', '1'), ['sAMAccountName'])
DELEGATION = search(ext('userAccountControl', '1.2.840.113556.1.4.803', '524288'))
NORMAL = search(AND(eq('objectClass', 'user'), eq('sAMAccountName', 'alice')), ['mail', 'displayName'])


# ---------- parsing ----------

def test_parse_search_metadata():
    [m] = parse_ldap(KERBEROAST)
    assert m['op'] == 'search' and m['base'] == 'DC=corp,DC=example' and m['scope'] == 'subtree'
    assert m['filter_attributes'] == ['samaccounttype', 'serviceprincipalname']
    assert m['attributes'] == ['servicePrincipalName', 'sAMAccountName'] and m['markers'] == ['spn']


def test_reconnaissance_markers():
    for payload, marker in ((ASREP, 'asrep'), (TRUSTS, 'trusts'), (LAPS, 'laps'), (ADMINS, 'admins'),
                            (DELEGATION, 'delegation')):
        assert parse_ldap(payload)[0]['markers'] == [marker], marker
    assert parse_ldap(NORMAL)[0]['markers'] == []
    assert parse_ldap(search(eq('memberOf', 'CN=Domain Admins,CN=Users,DC=corp')))[0]['markers'] == ['admins']


def test_binds():
    [m] = parse_ldap(bind_simple())
    assert m == {'op': 'bind', 'method': 'simple', 'mechanism': None, 'anonymous': False, 'password': True}
    [m] = parse_ldap(bind_simple(dn=b'', password=b''))
    assert m['anonymous'] is True and m['password'] is False
    [m] = parse_ldap(bind_sasl())
    assert m['method'] == 'sasl' and m['mechanism'] == 'GSS-SPNEGO' and m['password'] is False


def test_several_messages_responses_and_damage():
    # a search result entry (APPLICATION 4) from the server is not a request and is skipped
    response = tlv(0x30, tlv(0x02, b'\x01') + tlv(0x64, tlv(0x04, b'CN=x') + tlv(0x30, b'')))
    msgs = parse_ldap(bind_sasl() + KERBEROAST + response + ADMINS)
    assert [m['op'] for m in msgs] == ['bind', 'search', 'search']
    # truncated in the middle of the second message: the first is kept
    assert [m['op'] for m in parse_ldap(KERBEROAST + ADMINS[:-5])] == ['search']
    assert parse_ldap(b'\x00\x00\x01\x00' + b'\x05' * 40) == []              # sealed SASL buffer
    assert parse_ldap(b'') == [] and parse_ldap(b'\x30\x84\xff\xff\xff\xff') == []
    assert parse_lateral('TCP', 389, KERBEROAST)[0] == 'ldap'
    assert parse_lateral('TCP', 3268, KERBEROAST)[0] == 'ldap'
    assert parse_lateral('UDP', 389, KERBEROAST)[0] == 'ldap'
    assert parse_lateral('TCP', 636, KERBEROAST) == (None, None)


def test_deeply_nested_filter_is_bounded():
    flt = present('servicePrincipalName')
    for _ in range(40):
        flt = AND(flt)
    [m] = parse_ldap(search(flt))
    assert m['markers'] == []                                   # beyond the depth limit nothing is read


def test_filter_text_form():
    terms = parse_filter_text('(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))')
    assert terms == [('objectcategory', 'person', None), ('useraccountcontrol', '4194304', '1.2.840.113556.1.4.803')]
    assert ldap_markers(terms, []) == ['asrep']
    assert ldap_markers(parse_filter_text('(&(objectClass=user)(servicePrincipalName=*))'), []) == ['spn']


# ---------- detectors ----------

def test_recon_learned_then_reported():
    det = LateralDetector(clock=lambda: T0)
    assert det.observe_ldap(WS, DC, parse_ldap(KERBEROAST), ts=T0) == []          # learning: WS is a known user
    assert det.observe_ldap(WS, DC, parse_ldap(KERBEROAST), ts=T0 + WEEK + 10) == []
    [f] = det.observe_ldap('10.0.0.66', DC, parse_ldap(KERBEROAST), ts=T0 + WEEK + 10)
    assert f.kind == 'ldap_recon' and f.technique == 'T1558.003' and f.details['protocol'] == 'ldap'
    assert 'Kerberoasting' in f.evidence and f.details['base'] == 'DC=corp,DC=example'
    [f] = det.observe_ldap('10.0.0.66', DC, parse_ldap(ASREP), ts=T0 + WEEK + 20)
    assert f.technique == 'T1558.004'
    assert det.observe_ldap('10.0.0.66', DC, parse_ldap(NORMAL), ts=T0 + WEEK + 30) == []
    assert det.observe_ldap('8.8.8.8', DC, parse_ldap(KERBEROAST), ts=T0 + WEEK + 40) == []   # external source


def test_enumeration_reported_even_while_learning():
    det = LateralDetector(clock=lambda: T0)
    out = []
    for i, payload in enumerate((KERBEROAST, ADMINS, TRUSTS, LAPS)):
        out += det.observe_ldap(WS, DC, parse_ldap(payload), ts=T0 + i)
    [f] = out
    assert f.kind == 'ldap_enumeration' and f.technique == 'T1087.002'
    assert f.details['searches'] == ['admins', 'spn', 'trusts']
    # spread over more than ten minutes, three kinds are not a burst
    det = LateralDetector(clock=lambda: T0)
    out = []
    for i, payload in enumerate((KERBEROAST, ADMINS, TRUSTS)):
        out += det.observe_ldap(WS, DC, parse_ldap(payload), ts=T0 + i * 400)
    assert out == []


def test_cleartext_bind_once_a_day_and_never_confirmed_alone():
    det = LateralDetector(clock=lambda: T0)
    [f] = det.observe_ldap(WS, DC, parse_ldap(bind_simple()), ts=T0)
    assert f.kind == 'ldap_cleartext_bind' and f.probability < 0.5 and 'Winter' not in f.evidence
    assert det.observe_ldap(WS, DC, parse_ldap(bind_simple()), ts=T0 + 3600) == []
    assert len(det.observe_ldap(WS, DC, parse_ldap(bind_simple()), ts=T0 + 86401)) == 1
    assert det.observe_ldap(WS, DC, parse_ldap(bind_simple(dn=b'', password=b'')), ts=T0) == []
    assert det.observe_ldap(WS, DC, parse_ldap(bind_sasl()), ts=T0) == []


def test_pipeline_and_incident_checklist():
    pipe = DetectionPipeline(models=False, clock=lambda: T0, lateral=LateralDetector(clock=lambda: T0 - WEEK - 1))
    service, parsed, findings = pipe.observe_lateral('10.0.0.66', DC, 'TCP', 389, KERBEROAST, ts=T0)
    assert service == 'ldap' and parsed[0]['markers'] == ['spn'] and findings[0].kind == 'ldap_recon'
    steps = checklist(['ldap_recon'], '10.0.0.66', [])
    assert any('Active Directory' in s for s in steps)


def test_capture_routes_ldap_requests():
    small = bytes(Ether() / IP(src=WS, dst=DC) / TCP(sport=50000, dport=389, flags='PA') / Raw(KERBEROAST))
    big = bytes(Ether() / IP(src=WS, dst=DC) / TCP(sport=50000, dport=389, flags='PA') / Raw(b'\x00' * 1400))
    reply = bytes(Ether() / IP(src=DC, dst=WS) / TCP(sport=389, dport=50000, flags='PA') / Raw(KERBEROAST))
    cldap = bytes(Ether() / IP(src=WS, dst=DC) / UDP(sport=50000, dport=389) / Raw(KERBEROAST))
    assert afpacket.parse(small)[6] is True and afpacket.parse(cldap)[6] is True
    assert afpacket.parse(big)[6] is False                    # bulk / sealed traffic stays on the fast path
    assert afpacket.parse(reply)[6] is False                  # server replies are not inspected (TCP)


def test_zeek_ldap_logs():
    pipe = DetectionPipeline(models=False, clock=lambda: T0, lateral=LateralDetector(clock=lambda: T0 - WEEK - 1))
    feeder = ZeekFeeder(pipe)
    ids = {'id.orig_h': '10.0.0.66', 'id.resp_h': DC, 'id.orig_p': 50000, 'id.resp_p': 389, 'ts': T0}
    found = feeder.feed('ldap_search', {**ids, 'base_object': 'DC=corp,DC=example', 'scope': 'tree',
                                        'filter': '(&(objectClass=user)(servicePrincipalName=*))',
                                        'attributes': ['servicePrincipalName']})
    assert [f.kind for f in found] == ['ldap_recon']
    found = feeder.feed('ldap', {**ids, 'opcode': 'bind simple', 'object': 'CN=svc-app', 'argument': 'REDACTED'})
    assert [f.kind for f in found] == ['ldap_cleartext_bind']
    assert feeder.feed('ldap', {**ids, 'opcode': 'bind SASL', 'object': ''}) == []
