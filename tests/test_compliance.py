"""Compliance packs: control status, live evidence, reports and PDF (Phase 7)."""
import json
import time

import pytest

from compliance import evidence, packs
from compliance.pdf import render


def ev(status, summary='x'):
    return {'status': status, 'summary': summary, 'data': {}}


def test_control_status_combines_evidence():
    e = {'a': ev('met'), 'b': ev('partial'), 'c': ev('gap'), 'd': ev('n/a')}
    assert packs.control_status(e, []) == 'manual'
    assert packs.control_status(e, ['a']) == 'met'
    assert packs.control_status(e, ['a', 'd']) == 'met'             # n/a does not count against a control
    assert packs.control_status(e, ['a', 'b']) == 'partial'
    assert packs.control_status(e, ['a', 'c']) == 'partial'
    assert packs.control_status(e, ['c']) == 'gap'
    assert packs.control_status(e, ['d']) == 'n/a'


def test_every_mapped_evidence_key_has_a_collector():
    for name, pack in packs.PACKS.items():
        for ref, title, keys in pack['controls']:
            assert set(keys) <= set(evidence.COLLECTORS), (name, ref)
            assert title and ref


def test_report_on_a_fresh_device_is_honest():
    r = packs.report('iso27001')
    assert r['disclaimer'].startswith('Documentation support only')
    assert sum(r['totals'].values()) == len(packs.PACKS['iso27001']['controls'])
    by_id = {c['id']: c for c in r['controls']}
    assert by_id['A.5.1']['status'] == 'manual' and by_id['A.6.3']['status'] == 'manual'
    assert by_id['A.5.7']['status'] == 'gap'                           # no threat-intel feed configured in tests
    assert by_id['A.8.13']['status'] == 'gap'                          # no backup recorded
    assert by_id['A.8.13']['evidence'][0]['summary'].startswith('no backup recorded')


def test_a_broken_collector_does_not_break_the_report(monkeypatch):
    def boom():
        raise RuntimeError('database locked')
    monkeypatch.setitem(evidence.COLLECTORS, 'siem', boom)
    out = evidence.collect(['siem'])
    assert out['siem']['status'] == 'partial' and 'database locked' in out['siem']['summary']


def test_backups_are_recorded_and_become_evidence(tmp_path, monkeypatch):
    from ops import backup
    monkeypatch.setenv('SENTINEL_BACKUP_LOG', str(tmp_path / 'backup_log.json'))
    (tmp_path / 'etc').mkdir()
    (tmp_path / 'state').mkdir()
    (tmp_path / 'etc' / 'sentinel.env').write_text('X=1\n')
    backup.create(str(tmp_path / 'b.seab'), 'a long enough passphrase', etc_dir=str(tmp_path / 'etc'),
                  state_dir=str(tmp_path / 'state'))
    assert backup.last_backup()['file'].endswith('b.seab')
    assert evidence.backup()['status'] == 'met'
    log = json.loads((tmp_path / 'backup_log.json').read_text())
    log[-1]['ts'] = time.time() - 10 * 86400
    (tmp_path / 'backup_log.json').write_text(json.dumps(log))
    assert evidence.backup()['status'] == 'partial'


def test_mfa_evidence_names_who_still_has_to_enrol(monkeypatch):
    from core import auth
    monkeypatch.setenv('SENTINEL_MFA_ROLES', 'operator,admin')
    auth.get_store().create_user('adam', 'correct horse battery 9', 'admin')
    out = evidence.mfa()
    assert out['status'] == 'partial' and 'adam' in out['summary']
    monkeypatch.setenv('SENTINEL_MFA_ROLES', 'admin')
    assert evidence.mfa()['status'] == 'gap'


def test_all_packs_render_as_pdf():
    for name in packs.PACKS:
        pdf = render(packs.report(name))
        assert pdf.startswith(b'%PDF-1.4') and pdf.rstrip().endswith(b'%%EOF') and len(pdf) > 2000


def test_unknown_pack():
    with pytest.raises(ValueError, match='unknown pack'):
        packs.report('soc2')
