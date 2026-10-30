import copy
import time

import pytest
from cryptography import x509

from common import pki, protocol, signing
from sensor.buffer import DiskBuffer
from sensor.enforcer import Enforcer


# ---------- certificates ----------

def test_sensor_certificate_cn_is_chosen_by_the_brain():
    ca_key, ca_cert = pki.generate_ca()
    key, csr = pki.make_csr('i-am-the-brain')     # a sensor asking for a misleading name
    cert = pki.sign_sensor_csr(ca_key, ca_cert, csr, 'sensor-abcd1234')
    assert pki.common_name(cert) == 'sensor-abcd1234'
    parsed = pki.load_cert(cert)
    assert parsed.issuer == pki.load_cert(ca_cert).subject
    eku = parsed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert parsed.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_server_certificate_names_and_fingerprint():
    ca_key, ca_cert = pki.generate_ca()
    _, cert = pki.issue_server_cert(ca_key, ca_cert, ['brain.local'], ['192.0.2.10'])
    san = pki.load_cert(cert).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert 'brain.local' in san.get_values_for_type(x509.DNSName)
    assert len(pki.fingerprint(cert)) == 64
    der = pki.load_cert(cert).public_bytes(pki.serialization.Encoding.DER)
    assert pki.fingerprint(der) == pki.fingerprint(cert)


def test_garbage_csr_is_rejected():
    ca_key, ca_cert = pki.generate_ca()
    with pytest.raises(ValueError):
        pki.sign_sensor_csr(ca_key, ca_cert, 'not a csr', 'sensor-1')


# ---------- command signatures ----------

@pytest.fixture(scope='module')
def keypair():
    return signing.generate_keypair()


def test_signature_round_trip(keypair):
    private, public = keypair
    env = signing.sign(private, {'a': 1, 'b': [2, 3]}, public)
    assert signing.verify(public, env) == {'a': 1, 'b': [2, 3]}
    assert env['kid'] == signing.key_id(public)


def test_tampered_or_foreign_signature_fails(keypair):
    private, public = keypair
    env = signing.sign(private, {'action': 'block', 'ip': '198.51.100.1'})
    bad = copy.deepcopy(env)
    bad['payload']['ip'] = '198.51.100.2'
    with pytest.raises(signing.SignatureError):
        signing.verify(public, bad)
    other_private, _ = signing.generate_keypair()
    with pytest.raises(signing.SignatureError):
        signing.verify(public, signing.sign(other_private, env['payload']))
    for junk in (None, {}, {'payload': {}, 'sig': '!!!'}, {'payload': 'x', 'sig': ''}):
        with pytest.raises(signing.SignatureError):
            signing.verify(public, junk)


# ---------- enforcer ----------

class FakeFirewall:
    def __init__(self, whitelist=()):
        self.calls, self.whitelist = [], set(whitelist)

    def add_block(self, ip, ttl=None, reason=''):
        if ip in self.whitelist:
            raise ValueError(f'refusing to block whitelisted IP: {ip}')
        self.calls.append(('block', ip, reason))
        return {'ip': ip, 'dry_run': True}

    def remove_block(self, ip):
        self.calls.append(('unblock', ip))
        return {'removed': 1}

    def rollback_blocks(self, reason=''):
        self.calls.append(('rollback',))
        return {'removed': 0}


@pytest.fixture
def enforcer(tmp_path, keypair):
    fw = FakeFirewall(whitelist={'192.0.2.1'})
    return Enforcer('sensor-1', keypair[1], str(tmp_path / 'state.json'), firewall_module=fw), fw


def cmd(keypair, seq, action='block', ip='198.51.100.7', sensor='sensor-1', now=None):
    return signing.sign(keypair[0], protocol.make_command(sensor, seq, action, ip=ip, now=now))


def test_valid_command_is_applied(enforcer, keypair):
    enf, fw = enforcer
    assert enf.apply(cmd(keypair, 1))['status'] == 'applied'
    assert fw.calls == [('block', '198.51.100.7', 'brain:command')]
    assert enf.last_seq() == 1


def test_replayed_command_is_rejected_even_after_restart(enforcer, keypair, tmp_path):
    enf, fw = enforcer
    env = cmd(keypair, 1)
    enf.apply(env)
    assert enf.apply(env)['status'] == 'rejected'
    restarted = Enforcer('sensor-1', keypair[1], str(tmp_path / 'state.json'), firewall_module=fw)
    r = restarted.apply(env)
    assert r['status'] == 'rejected' and 'replayed' in r['detail']
    assert enf.apply(cmd(keypair, 1, ip='198.51.100.8'))['status'] == 'rejected'  # lower/equal seq, new content
    assert len(fw.calls) == 1


def test_forged_command_is_rejected(enforcer, keypair):
    enf, fw = enforcer
    env = cmd(keypair, 5)
    env['payload']['ip'] = '203.0.113.66'
    r = enf.apply(env)
    assert r['status'] == 'rejected' and 'forged' in r['detail']
    attacker_private, _ = signing.generate_keypair()
    r = enf.apply(signing.sign(attacker_private, protocol.make_command('sensor-1', 6, 'rollback')))
    assert r['status'] == 'rejected' and fw.calls == []
    assert enf.last_seq() == 0  # a rejected command never consumes a sequence number


def test_expired_or_misaddressed_command_is_rejected(enforcer, keypair):
    enf, fw = enforcer
    old = time.time() - protocol.COMMAND_TTL_SECONDS - 10
    assert 'expired' in enf.apply(cmd(keypair, 1, now=old))['detail']
    assert 'another sensor' in enf.apply(cmd(keypair, 2, sensor='sensor-2'))['detail']
    assert fw.calls == []


def test_local_whitelist_still_wins(enforcer, keypair):
    enf, fw = enforcer
    r = enf.apply(cmd(keypair, 1, ip='192.0.2.1'))
    assert r['status'] == 'refused' and 'whitelisted' in r['detail']
    assert fw.calls == [] and enf.last_seq() == 1


def test_unblock_and_rollback(enforcer, keypair):
    enf, fw = enforcer
    enf.apply(cmd(keypair, 1, action='unblock'))
    enf.apply(signing.sign(keypair[0], protocol.make_command('sensor-1', 2, 'rollback')))
    assert fw.calls == [('unblock', '198.51.100.7'), ('rollback',)]


def test_make_command_validates():
    with pytest.raises(ValueError):
        protocol.make_command('s', 1, 'format_disk')
    with pytest.raises(ValueError):
        protocol.make_command('s', 1, 'block')
    with pytest.raises(ValueError):
        protocol.make_command('s', 1, 'block', ip='not-an-ip')


# ---------- disk buffer ----------

def test_buffer_survives_reopen_and_acks(tmp_path):
    path = str(tmp_path / 'buf.db')
    b = DiskBuffer(path)
    b.put([{'n': i} for i in range(5)])
    b.close()
    b = DiskBuffer(path)
    batch = b.peek(3)
    assert [r['n'] for _, r in batch] == [0, 1, 2]
    b.ack([rid for rid, _ in batch])
    assert len(b) == 2 and [r['n'] for _, r in b.peek()] == [3, 4]


def test_buffer_drops_oldest_beyond_limit(tmp_path):
    b = DiskBuffer(str(tmp_path / 'buf.db'), max_records=3)
    b.put([{'n': i} for i in range(5)])
    assert [r['n'] for _, r in b.peek()] == [2, 3, 4]
    assert b.dropped() == 2
