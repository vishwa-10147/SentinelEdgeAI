"""Community threat sharing: anonymised, multi-site, signed, and second-hand trust (Phase 11)."""
import json
import time

import pytest

from common import signing
from detection.detectors import IntelDetector
from fleet import manage
from fleet.store import FleetStore
from intel import sharing
from intel.store import IntelStore

NOW = 1_800_000_000


def alert(site, src, dst, kind='beaconing', score=82, ts=NOW - 3600):
    return {'site': site, 'ts': ts, 'type': kind, 'score': score, 'src_ip': src, 'dst_ip': dst}


def test_only_internet_addresses_seen_at_several_sites():
    cfg = sharing.save_config({'enabled': True, 'min_sites': 2, 'never_share': ['198.51.0.0/16']})
    alerts = [alert('a', '10.0.0.5', '45.77.10.20'), alert('b', '192.168.1.9', '45.77.10.20'),   # 2 sites: shared
              alert('a', '10.0.0.5', '45.77.10.21'),                                             # 1 site: not
              alert('a', '10.0.0.6', '100.64.1.1'), alert('b', '10.0.0.7', '100.64.1.1'),        # CGNAT: never
              alert('a', '10.0.0.6', '198.51.7.7'), alert('b', '10.0.0.7', '198.51.7.7'),        # never_share
              alert('a', '10.0.0.6', '23.1.1.1', score=40), alert('b', '10.0.0.7', '23.1.1.1', score=40),  # low score
              alert('a', '10.0.0.6', '23.1.1.2', kind='new_device'), alert('b', '10.0.0.7', '23.1.1.2', kind='new_device'),
              alert('a', '10.0.0.6', '23.1.1.3', ts=NOW - 30 * 86400), alert('b', '10.0.0.7', '23.1.1.3')]  # too old
    out = sharing.collect(alerts, cfg, now=NOW)
    assert [i['value'] for i in out] == ['45.77.10.20']
    assert out[0]['kinds'] == ['beaconing'] and set(out[0]) == {'type', 'value', 'kinds', 'first_seen_day'}


def test_signed_bundle_round_trip_and_tampering():
    cfg = sharing.save_config({'enabled': True, 'publisher': 'Example MSP'})
    private, public = signing.generate_keypair()
    ind = [{'type': 'ip', 'value': '45.77.10.20', 'kinds': ['beaconing'], 'first_seen_day': '2027-01-15'}]
    doc = sharing.sign_bundle(sharing.bundle(ind, cfg, now=NOW), private, public)
    text = json.dumps(doc)
    assert '10.0.0.' not in text and 'site' not in text.lower()                 # nothing about the sites
    stix = sharing.verify_bundle(text, public)
    from intel.store import parse_stix
    assert [(i['type'], i['value']) for i in parse_stix(stix)] == [('ip', '45.77.10.20')]
    forged = json.loads(text)
    forged['payload']['objects'][1]['pattern'] = "[ipv4-addr:value = '8.8.8.8']"
    with pytest.raises(ValueError, match='signature'):
        sharing.verify_bundle(forged, public)
    with pytest.raises(ValueError, match='different key'):
        sharing.verify_bundle(text, signing.generate_keypair()[1])


def test_community_feed_is_checked_and_second_hand(tmp_path):
    private, public = signing.generate_keypair()
    cfg = sharing.save_config({'enabled': True})
    ind = [{'type': 'ip', 'value': '45.77.10.20', 'kinds': ['beaconing'], 'first_seen_day': '2027-01-15'}]
    path = tmp_path / 'community.json'
    path.write_text(json.dumps(sharing.sign_bundle(sharing.bundle(ind, cfg), private, public)))
    store = IntelStore()
    with pytest.raises(ValueError, match='public key'):
        store.add_feed('msp', f'file://{path}', 'signed-stix')
    store.add_feed('msp', f'file://{path}', 'signed-stix', public_key=public)
    assert store.update_feeds() == {'msp': 1}
    assert store.match_ip('45.77.10.20') == ('community:msp', 'beaconing')
    [f] = IntelDetector(store=store).observe({'src': '10.0.0.5', 'dst': '45.77.10.20', 'ts': NOW})
    assert (f.severity, f.probability) == sharing.COMMUNITY_TRUST              # never an automatic response alone
    # a bundle re-signed by someone else is refused; the previous indicators stay
    other_private, other_public = signing.generate_keypair()
    path.write_text(json.dumps(sharing.sign_bundle(sharing.bundle(ind, cfg), other_private, other_public)))
    assert store.update_feeds()['msp'].startswith('error')
    assert store.match_ip('45.77.10.20') is not None


def test_fleet_distributes_and_exports(tmp_path):
    st = FleetStore()
    for site in ('s1', 's2'):
        st.add_alerts(site, [{'ts': int(time.time()) - 600, 'type': 'beaconing', 'score': 85,
                              'src_ip': '10.0.0.9', 'dst_ip': '45.77.10.20'}])
    assert manage.share('status', st=st)['indicators'] == 1
    from fleet import server
    server._shared_cache.update(at=0, value=None)
    assert server._shared_intel(st, time.time()) == {'fleet_intel': None}           # off by default
    manage.share('enable', st=st, min_sites=2, never_share=['203.0.113.0/24'])
    shared = server._shared_intel(st, time.time())['fleet_intel']
    assert [i['value'] for i in shared['indicators']] == ['45.77.10.20']
    # the site agent loads it as the 'fleet' source, and clears it when sharing stops
    from fleet import agent
    from intel.store import get_store
    assert agent._fleet_intel({'fleet_intel': shared}) == 1
    assert get_store().match_ip('45.77.10.20')[0] == 'fleet'
    [f] = IntelDetector(store=get_store()).observe({'src': '10.0.0.5', 'dst': '45.77.10.20', 'ts': time.time()})
    assert (f.severity, f.probability) == sharing.SOURCE_TRUST['fleet']
    assert agent._fleet_intel({'fleet_intel': None}) == 0
    get_store()._cache = None
    assert get_store().match_ip('45.77.10.20') is None
    out = manage.share('export', st=st, out=str(tmp_path / 'b.json'))
    doc = json.loads((tmp_path / 'b.json').read_text())
    assert out['indicators'] == 1 and sharing.verify_bundle(doc, manage.share('key')['public_key'])
