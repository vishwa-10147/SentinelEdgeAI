"""Peer profiles, the device trust score and containment (Phase 7, zero-trust).

The kernel side is covered by tests/firewall_netns/run_containment_netns.sh.
"""
import json
import time

import pytest

import core.firewall as fw
from detection import peers
from detection.peers import PeerStore, learned
from enforcement import protected, trust

NOW = 1_800_000_000.0
DAY = 86400
DEV, PEER, NAS = '192.168.1.50', '192.168.1.10', '192.168.1.20'


@pytest.fixture(autouse=True)
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'ROOT', str(tmp_path))
    monkeypatch.setattr(fw, 'FIREWALL_DRY_RUN', True)
    monkeypatch.setenv('SENTINEL_BRIDGE', '0')
    monkeypatch.setattr(protected, 'why_protected', lambda ip, hosts=None: 'gateway' if ip == '192.168.1.1' else None)


def flow(dst, dport, proto='TCP', src=DEV, ts=NOW):
    return {'src': src, 'dst': dst, 'proto': proto, 'dport': dport, 'ts': ts}


# ---------- peer profiles ----------

def test_profile_keeps_internal_peers_and_collapses_the_internet():
    s = PeerStore()
    s.observe(flow(PEER, 445, ts=NOW - 8 * DAY))
    s.observe(flow('93.184.216.34', 443))
    s.observe(flow('142.250.1.1', 443))                    # another web server: same (tcp, 443)
    s.observe(flow(NAS, 53, 'UDP'))
    s.observe(flow(PEER, 0))                               # no port: ignored
    s.observe(flow(PEER, 1, 'ICMP'))                       # not TCP/UDP: ignored
    s.observe(flow(PEER, 80, src='93.184.216.34'))         # sources on the internet have no profile
    p = s.profile(DEV)
    assert p['internal'] == [(PEER, 'tcp', 445), (NAS, 'udp', 53)]
    assert p['external'] == [('tcp', 443)]
    assert learned(p, now=NOW) and not learned(p, now=NOW - 2 * DAY)
    assert s.profile('93.184.216.34') is None


def test_profiles_are_capped(monkeypatch):
    monkeypatch.setattr(peers, 'MAX_INTERNAL', 5)
    s = PeerStore()
    for port in range(1000, 1050):
        s.observe(flow(PEER, port))
    assert len(s.profile(DEV)['internal']) == 5
    s.close()
    again = PeerStore()                                    # the cap holds across restarts
    again.observe(flow(PEER, 2000))
    assert len(again.profile(DEV)['internal']) == 5


def test_pipeline_feeds_the_peer_store():
    from detection.pipeline import DetectionPipeline
    pipe = DetectionPipeline(models=False, clock=lambda: NOW, peers=PeerStore())
    pipe.observe_flow(dict(flow(PEER, 22), duration=1, forward_bytes=100, backward_bytes=100))
    assert pipe.peers.profile(DEV)['internal'] == [(PEER, 'tcp', 22)]


# ---------- trust score ----------

DEVICE = {'mac': 'aa:bb:cc:00:11:22', 'vendor': 'Raspberry Pi Trading', 'hostname': 'printer', 'first_seen': NOW - 30 * DAY}


def alert(risk, age, kind='port_scan', src=DEV):
    return {'src': src, 'ts': NOW - age, 'risk': risk, 'kind': kind}


def test_known_long_lived_quiet_device_is_trusted():
    t = trust.score_device(DEV, NOW, DEVICE)
    assert t['score'] == 90 and t['level'] == 'trusted' and t['recommendation'] == 'none'
    assert '+20 seen for 30.0 days' in t['reasons']


def test_unknown_new_device_is_watched():
    t = trust.score_device(DEV, NOW, None, first_seen=NOW - 3600)
    assert t['level'] == 'watch' and t['score'] == 40
    assert '-10 no MAC address seen for this IP' in t['reasons']


def test_recent_alerts_lower_trust_and_fade():
    hot = trust.score_device(DEV, NOW, DEVICE, [alert(90, 60), alert(85, 120, 'brute_force'),
                                                alert(80, 300, 'beaconing'), alert(95, 30, 'exfiltration')])
    assert hot['level'] == 'untrusted' and 'strongest: exfiltration, risk 95' in hot['reasons'][-1]
    cold = trust.score_device(DEV, NOW, DEVICE, [alert(90, 5 * DAY), alert(85, 5 * DAY)])
    assert cold['score'] > hot['score'] and cold['level'] == 'trusted'
    old = trust.score_device(DEV, NOW, DEVICE, [alert(100, 8 * DAY)])         # outside the 7-day window
    assert old['score'] == 90


def test_repeats_of_one_kind_do_not_stack():
    one = trust.score_device(DEV, NOW, DEVICE, [alert(90, 60)])
    many = trust.score_device(DEV, NOW, DEVICE, [alert(90, 60 + i) for i in range(400)])
    assert many['score'] == one['score'] == 63 and many['level'] == 'watch'
    assert '400 alerts of 1 kind' in many['reasons'][-1]


def test_randomised_mac_earns_no_vendor_bonus_and_protected_hosts_get_no_response():
    t = trust.score_device(DEV, NOW, dict(DEVICE, vendor='Private (randomised MAC)'))
    assert t['score'] == 85
    alerts = [alert(95, 10, k) for k in ('a', 'b', 'c', 'd')]
    g = trust.score_device(DEV, NOW, None, alerts, profile_learned=True, protected='gateway')
    assert g['level'] == 'untrusted' and g['recommendation'] == 'none (protected host)' and g['protected']


def test_false_positive_kinds_are_ignored():
    alerts = [alert(90, 60), alert(90, 60), alert(90, 60), alert(90, 60)]
    t = trust.score_device(DEV, NOW, DEVICE, alerts, false_positive={(DEV, 'port_scan')})
    assert t['score'] == 90 and '4 alerts ignored (marked false positive)' in t['reasons']


def test_recommendation_depends_on_the_profile_and_restrictions():
    alerts = [alert(95, 10, k) for k in ('port_scan', 'brute_force', 'dga')]
    assert trust.score_device(DEV, NOW, None, alerts, profile_learned=True)['recommendation'] == 'contain'
    assert trust.score_device(DEV, NOW, None, alerts)['recommendation'].startswith('quarantine')
    q = trust.score_device(DEV, NOW, DEVICE, restrictions=[{'ip': DEV, 'kind': 'quarantine'}])
    assert q['score'] == 0 and q['recommendation'] == 'keep restricted'
    c = trust.score_device(DEV, NOW, DEVICE, restrictions=[{'ip': DEV, 'kind': 'contain'}])
    assert c['score'] == 30 and 'currently contained to its learned peers' in c['reasons']


def test_alert_rows_from_both_storage_paths():
    rows = [{'timestamp': NOW, 'src_ip': DEV, 'score': 80, 'details': str({'attack_type': 'brute_force'})},
            {'timestamp': NOW, 'src_ip': None, 'score': 85, 'details': json.dumps({'initiator_ip': NAS, 'attack_type': 'dga'})},
            {'timestamp': NOW, 'src_ip': None, 'score': 50, 'details': 'garbage'},
            {'timestamp': NOW, 'src_ip': PEER, 'score': 60, 'details': json.dumps({'attack_type': 'NONE'})}]
    assert trust.normalise_alerts(rows) == [{'src': DEV, 'ts': NOW, 'risk': 80.0, 'kind': 'brute_force'},
                                            {'src': NAS, 'ts': NOW, 'risk': 85.0, 'kind': 'dga'},
                                            {'src': PEER, 'ts': NOW, 'risk': 60.0, 'kind': 'anomaly'}]


def test_scores_lists_every_known_device(monkeypatch):
    s = PeerStore()
    s.observe(flow(PEER, 445, ts=time.time() - 8 * DAY))
    s.close()
    monkeypatch.setattr(trust, '_load_alerts', lambda limit=5000: [
        {'src': ip, 'ts': time.time() - 60, 'risk': 95, 'kind': k} for ip in (NAS, '127.0.0.1') for k in ('a', 'b', 'c')])
    out = trust.scores()
    assert [d['ip'] for d in out] == [NAS, DEV]                                # least trusted first, no loopback
    assert out[0]['level'] == 'untrusted' and out[1]['profile_learned'] is True


# ---------- containment ----------

def test_contain_needs_a_learned_ipv4_profile():
    with pytest.raises(ValueError, match='no learned peer profile'):
        fw.add_restriction('contain', DEV, ttl=60)
    with pytest.raises(ValueError, match='IPv4 only'):
        fw.add_restriction('contain', 'fd00::5', ttl=60)
    with pytest.raises(ValueError, match='protected host'):
        fw.add_restriction('contain', '192.168.1.1', ttl=60)
    s = PeerStore()
    s.observe(flow(PEER, 445, ts=time.time() - 8 * DAY))
    s.close()
    item = fw.add_restriction('contain', DEV, ttl=60, reason='untrusted')
    assert item['kind'] == 'contain' and [r['ip'] for r in fw.list_restrictions()] == [DEV]
    assert fw.remove_restriction('contain', DEV) == {'removed': 1}


def test_contain_peer_sets_come_from_the_profiles():
    s = PeerStore()
    s.observe(flow(PEER, 445, ts=time.time() - 8 * DAY))
    s.observe(flow('93.184.216.34', 443))
    s.close()
    fw.add_restriction('contain', DEV, ttl=60)
    script = fw._contain_elements_script(bridge=True)
    assert f'add element inet sentinel contain_peers {{ {DEV} . {PEER} . tcp . 445 }}' in script
    assert f'add element bridge sentinel contain_ext {{ {DEV} . tcp . 443 }}' in script


def test_enforcement_script_wires_containment_in_both_tables():
    script = fw._enforcement_script(bridge=True)
    assert 'add rule inet sentinel enf_forward ip saddr @contain jump contain_check' in script
    assert 'add rule inet sentinel contain_check ct state established,related return' in script
    assert 'add rule bridge sentinel contain_check tcp flags & (syn | ack) != syn return' in script
    assert 'add rule bridge sentinel forward ip saddr @contain jump contain_check' in script
