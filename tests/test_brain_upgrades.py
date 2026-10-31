"""Sensor upgrades distributed by the brain over the mutual-TLS link (Phase 2)."""
import hashlib
import json
import os

import pytest

from brain import manage, upgrades
from sensor import uplink
from tests.test_brain_link import enrolled_uplink, env  # noqa: F401  (live brain fixture)


def package(tmp_path, version='9.1.0', body=b'not really a tarball, but bytes are bytes'):
    path = tmp_path / f'sentineledgeai-pi-{version}.tar.gz'
    path.write_bytes(body)
    (tmp_path / (path.name + '.sha256')).write_text(f'{hashlib.sha256(body).hexdigest()}  {path.name}\n')
    return str(path)


def test_staging_checks_the_name_and_the_checksum(env, tmp_path):
    with pytest.raises(ValueError, match='named'):
        bad = tmp_path / 'evil.tar.gz'
        bad.write_bytes(b'x')
        upgrades.stage_file(str(bad))
    pkg = package(tmp_path)
    with open(pkg, 'ab') as f:
        f.write(b'tampered')
    with pytest.raises(ValueError, match='checksum mismatch'):
        upgrades.stage_file(pkg)
    t = upgrades.stage_file(package(tmp_path / '..' / tmp_path.name, '9.1.1'))
    assert t['version'] == '9.1.1' and upgrades.offer('9.1.1') == {'version': None}
    assert upgrades.offer('2.4.1')['version'] == '9.1.1'


def test_sensor_downloads_verifies_and_stages(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    assert link.check_upgrade() is None                                 # nothing staged
    upgrades.stage_file(package(tmp_path))
    assert link.check_upgrade() == '9.1.0'
    up = os.path.join(uplink.sensor_dir(), 'upgrade')
    ready = json.load(open(os.path.join(up, 'ready.json')))
    assert ready['file'] == 'sentineledgeai-pi-9.1.0.tar.gz'
    body = open(os.path.join(up, ready['file']), 'rb').read()
    assert hashlib.sha256(body).hexdigest() == ready['sha256']
    assert open(os.path.join(up, ready['file'] + '.sha256')).read().split() == [ready['sha256'], ready['file']]
    assert link.check_upgrade() == '9.1.0'                              # already staged: no second download


def test_a_package_that_does_not_match_the_announced_checksum_is_discarded(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    t = upgrades.stage_file(package(tmp_path))
    with open(os.path.join(upgrades.releases_dir(), t['file']), 'ab') as f:   # changed after staging
        f.write(b'!')
    assert link.check_upgrade() is None
    up = os.path.join(uplink.sensor_dir(), 'upgrade')
    assert not os.path.exists(os.path.join(up, 'ready.json')) and not os.listdir(up)


def test_the_sensor_reports_its_version(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    link.send_health()
    assert manage.store().list_sensors()[0]['health']['version'] == uplink.local_version()


def test_stage_release_downloads_both_files(env, tmp_path):
    body = b'release bytes'
    name = 'sentineledgeai-pi-9.2.0.tar.gz'

    class Resp:
        def __init__(self, data, code=200):
            self.data, self.status_code = data, code

        def iter_content(self, n):
            yield self.data

    class Session:
        def get(self, url, **kw):
            if url.endswith('.sha256'):
                return Resp(f'{hashlib.sha256(body).hexdigest()}  {name}\n'.encode())
            return Resp(body)
    assert upgrades.stage_release('9.2.0', session=Session())['version'] == '9.2.0'
    with pytest.raises(ValueError, match='version'):
        upgrades.stage_release('latest', session=Session())
