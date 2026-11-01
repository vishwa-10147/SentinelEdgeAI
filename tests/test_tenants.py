"""MSP multi-tenancy on the fleet server: customers, scoped roles, branding, usage (Phase 11)."""
import sqlite3
import time

import pytest

from core import auth
from fleet import tenants
from fleet.store import FleetStore
from fleet.tenants import Scope

PASSWORD = 'correct horse battery staple 42'


@pytest.fixture()
def fleet(monkeypatch):
    st = FleetStore()
    tenants.create(st, 'acme', 'Acme Ltd')
    tenants.create(st, 'globex', 'Globex Corp')
    for g, t in (('acme-hq', 'acme'), ('globex-plants', 'globex')):
        st.put_group(g)
        tenants.assign_group(st, g, t)
    now = int(time.time())
    db = st._db()
    for sid, grp in (('s-acme', 'acme-hq'), ('s-globex', 'globex-plants'), ('s-default', 'default')):
        db.execute('INSERT INTO sites(id, name, cert_fp, grp, enrolled, last_seen) VALUES (?,?,?,?,?,?)',
                   (sid, sid, 'fp' + sid, grp, now - 86400, now))
    db.commit()
    for sid in ('s-acme', 's-globex'):
        st.add_report(sid, {'version': '2.17.0'})
        st.add_alerts(sid, [{'ts': now - 60, 'type': 'beaconing', 'score': 80, 'src_ip': '10.0.0.5',
                             'dst_ip': '45.77.10.20'}])
    store = auth.get_store()
    for user, role in (('msp', 'admin'), ('alice', 'admin'), ('olly', 'operator'), ('vic', 'viewer')):
        store.create_user(user, PASSWORD, role)
    tenants.member(st, 'alice', 'acme', 'admin')
    tenants.member(st, 'olly', 'acme', 'admin')            # capped by the console role: operator
    tenants.member(st, 'vic', 'globex', 'viewer')
    return st


def principal(user, role):
    return {'kind': 'user', 'username': user, 'role': role}


def test_migration_keeps_existing_fleets_in_default(tmp_path):
    path = str(tmp_path / 'old.db')
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE groups (name TEXT PRIMARY KEY, template TEXT, target_version TEXT,
        stages TEXT NOT NULL DEFAULT '[]', started INTEGER, paused TEXT, updated_by TEXT);
        INSERT INTO groups(name) VALUES ('default'), ('branch');""")
    db.close()
    st = FleetStore(path)
    assert st.tenant_of_group('branch') == 'default' and st.get_tenant('default')['name'] == 'Default'


def test_scope_rules(fleet):
    msp, alice, olly, vic = (Scope(principal(u, r), fleet) for u, r in
                             (('msp', 'admin'), ('alice', 'admin'), ('olly', 'operator'), ('vic', 'viewer')))
    assert msp.msp and msp.can('globex', 'admin') and msp.tenants() is None
    assert alice.can('acme', 'admin') and not alice.can('globex', 'viewer') and alice.tenants() == {'acme'}
    assert olly.role_in('acme') == 'operator' and not olly.can('acme', 'admin')     # capped by console role
    assert vic.can('globex', 'viewer') and not vic.can('globex', 'operator')
    with pytest.raises(PermissionError):
        alice.require_msp()
    # an API token owned by a customer account is scoped like its owner
    token = Scope({'kind': 'api_token', 'username': 'token:siem', 'owner': 'alice', 'role': 'admin'}, fleet)
    assert not token.msp and token.tenants() == {'acme'}


def test_branding_and_validation(fleet):
    t = tenants.brand(fleet, 'acme', display_name='Acme Security', accent='#1F6FEB', support='soc@acme.example')
    assert t['branding'] == {'display_name': 'Acme Security', 'accent': '#1f6feb', 'support': 'soc@acme.example'}
    for bad in ({'accent': 'red'}, {'support': 'javascript:alert(1)'}, {'display_name': 'x' * 100}):
        with pytest.raises(tenants.TenantError):
            tenants.brand(fleet, 'acme', **bad)
    with pytest.raises(tenants.TenantError):
        tenants.create(fleet, 'Bad Id!', 'x')
    with pytest.raises(tenants.TenantError, match='no console account'):
        tenants.member(fleet, 'nobody', 'acme', 'viewer')


def test_usage_per_tenant(fleet):
    month = time.strftime('%Y-%m', time.gmtime())
    rows = {r['tenant']: r for r in fleet.usage(month)}
    assert rows['acme']['sites'] == 1 and rows['acme']['site_days'] == 1 and rows['acme']['alerts'] == 1
    assert rows['globex']['sites'] == 1 and rows['default']['site_days'] == 0
    csv_text = tenants.usage(fleet, month, Scope(principal('alice', 'admin'), fleet), fmt='csv')
    assert csv_text.splitlines()[0] == 'month,tenant,name,sites,site_days,alerts,actions'
    assert len(csv_text.splitlines()) == 2 and ',acme,' in csv_text


def call(user, role, method, path, **kw):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    p = principal(user, role)
    for dep in (api.require_viewer, api.require_operator, api.require_admin):
        api.app.dependency_overrides[dep] = lambda p=p: p
    try:
        return getattr(TestClient(api.app), method)(path, **kw)
    finally:
        api.app.dependency_overrides.clear()


def test_api_is_scoped(fleet):
    ov = call('alice', 'admin', 'get', '/api/fleet').json()
    assert [s['id'] for s in ov['sites']] == ['s-acme'] and {g['name'] for g in ov['groups']} == {'acme-hq'}
    assert ov['scope'] == {'msp': False, 'roles': {'acme': 'admin'}} and ov['federated'] is None
    assert len(call('msp', 'admin', 'get', '/api/fleet').json()['sites']) == 3
    # another customer's site: history, actions, revoke are refused
    assert call('alice', 'admin', 'get', '/api/fleet/sites/s-globex/history').status_code == 403
    assert call('alice', 'admin', 'post', '/api/fleet/sites/s-globex/revoke').status_code == 403
    assert call('alice', 'admin', 'post', '/api/fleet/sites/s-globex/actions',
                json={'kind': 'block', 'ip': '45.77.10.20'}).status_code == 403
    assert call('vic', 'viewer', 'get', '/api/fleet/sites/s-globex/history').status_code == 200
    # an operator capped below admin cannot revoke even in its own customer
    assert call('olly', 'operator', 'post', '/api/fleet/sites/s-acme/actions',
                json={'kind': 'block', 'ip': '45.77.10.20'}).status_code == 200
    # alerts and actions only from the customer's sites
    alerts = call('alice', 'admin', 'get', '/api/fleet/alerts').json()['alerts']
    assert {a['site'] for a in alerts} == {'s-acme'}
    assert {a['site'] for a in call('vic', 'viewer', 'get', '/api/fleet/actions').json()['actions']} <= {'s-globex'}
    # MSP-wide settings and customer management are MSP staff only
    assert call('alice', 'admin', 'post', '/api/fleet/templates', json={'name': 't', 'preset': 'office'}).status_code == 403
    assert call('alice', 'admin', 'post', '/api/fleet/tenants', json={'id': 'mine', 'name': 'x'}).status_code == 403
    assert call('msp', 'admin', 'post', '/api/fleet/tenants', json={'id': 'initech', 'name': 'Initech',
                                                                   'accent': '#ff8800'}).json()['branding']['accent'] == '#ff8800'
    # a customer admin brands its own customer only; new groups land in its customer
    assert call('alice', 'admin', 'put', '/api/fleet/tenants/acme/branding', json={'display_name': 'Acme'}).status_code == 200
    assert call('alice', 'admin', 'put', '/api/fleet/tenants/globex/branding', json={'display_name': 'x'}).status_code == 403
    assert call('alice', 'admin', 'post', '/api/fleet/groups', json={'name': 'acme-branch'}).status_code == 200
    assert fleet.tenant_of_group('acme-branch') == 'acme'
    assert call('alice', 'admin', 'post', '/api/fleet/codes', json={'group': 'globex-plants'}).status_code == 403
    # usage: own customer only
    rows = call('alice', 'admin', 'get', '/api/fleet/usage').json()['usage']
    assert [r['tenant'] for r in rows] == ['acme']
    assert call('msp', 'admin', 'get', '/api/fleet/usage?month=2026-13').status_code == 400


def test_cli(fleet, capsys):
    from fleet.__main__ import main
    assert main(['tenant', 'create', 'umbrella', '--name', 'Umbrella', '--accent', '#00aa55']) == 0
    assert main(['tenant', 'assign', 'umbrella', '--group', 'default']) == 0
    assert fleet.tenant_of_site('s-default') == 'umbrella'
    assert main(['usage', '--csv']) == 0
    assert 'umbrella' in capsys.readouterr().out
