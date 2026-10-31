"""Phase 1 exit check: every endpoint has a role test.

ROUTES lists every HTTP route with the minimum role allowed to call it.
Adding a route without listing it here fails test_every_route_is_listed.
"""
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import core.auth as auth
import dashboard.auth_routes as auth_routes
import dashboard.dashboard_api as api

PASSWORD = 'correct horse battery'

# 'public' routes must work before sign-in (status, sign-in itself, the console)
ROUTES = {
    ('GET', '/'): 'public',
    ('GET', '/api/auth/status'): 'public',
    ('POST', '/api/auth/login'): 'public',
    ('POST', '/api/auth/refresh'): 'public',   # needs the refresh cookie + CSRF header
    ('POST', '/api/auth/logout'): 'public',    # needs the CSRF header
    ('GET', '/api/auth/me'): 'viewer',
    ('GET', '/api/auth/mfa'): 'viewer',
    ('POST', '/api/auth/mfa/setup'): 'viewer',
    ('POST', '/api/auth/mfa/enable'): 'viewer',
    ('POST', '/api/auth/password'): 'viewer',
    ('GET', '/metrics'): 'viewer',
    ('GET', '/openapi.json'): 'viewer',
    ('GET', '/api/alerts'): 'viewer',
    ('GET', '/api/live_stats'): 'viewer',
    ('GET', '/api/device_profiles'): 'viewer',
    ('GET', '/api/risk_timeline'): 'viewer',
    ('GET', '/api/flows'): 'viewer',
    ('GET', '/api/incidents/timeline'): 'viewer',
    ('GET', '/api/reports/security'): 'viewer',
    ('GET', '/api/health'): 'viewer',
    ('GET', '/api/device/{device_id}/logs'): 'viewer',
    ('GET', '/api/firewall/rules'): 'viewer',
    ('GET', '/api/firewall/actions'): 'viewer',
    ('GET', '/api/firewall/policy'): 'viewer',
    ('POST', '/api/alerts/explain'): 'analyst',
    ('POST', '/api/firewall/block'): 'operator',
    ('POST', '/api/firewall/unblock'): 'operator',
    ('POST', '/api/firewall/whitelist'): 'operator',
    ('POST', '/api/firewall/expire'): 'operator',
    ('POST', '/api/firewall/rollback'): 'operator',
    ('POST', '/api/demo/run'): 'operator',
    ('POST', '/api/demo/presenter'): 'operator',
    ('POST', '/api/firewall/policy'): 'admin',
    ('GET', '/api/users'): 'admin',
    ('POST', '/api/users'): 'admin',
    ('PATCH', '/api/users/{username}'): 'admin',
    ('DELETE', '/api/users/{username}'): 'admin',
    ('GET', '/api/tokens'): 'admin',
    ('POST', '/api/tokens'): 'admin',
    ('DELETE', '/api/tokens/{token_id}'): 'admin',
    ('GET', '/api/audit'): 'admin',
    ('GET', '/api/audit/verify'): 'admin',
    ('GET', '/api/setup'): 'admin',
    ('POST', '/api/setup'): 'admin',
    ('GET', '/api/brain/sensors'): 'viewer',
    ('GET', '/api/brain/commands'): 'viewer',
    ('GET', '/api/brain/flows'): 'viewer',
    ('POST', '/api/brain/codes'): 'admin',
    ('POST', '/api/brain/sensors/{sensor_id}/revoke'): 'admin',
    ('POST', '/api/brain/sensors/{sensor_id}/commands'): 'operator',
    ('GET', '/api/sensor/status'): 'viewer',
    ('POST', '/api/sensor/enroll'): 'admin',
    ('GET', '/quarantined'): 'public',
    ('GET', '/quarantined.css'): 'public',
    ('GET', '/api/enforcement/protected'): 'viewer',
    ('GET', '/api/devices/identity'): 'viewer',
    ('GET', '/api/ot/assets'): 'viewer',
    ('GET', '/api/trust'): 'viewer',
    ('GET', '/api/tuning'): 'viewer',
    ('GET', '/api/compliance'): 'admin',
    ('GET', '/api/compliance/{pack}'): 'admin',
    ('GET', '/api/compliance/{pack}/pdf'): 'admin',
    ('POST', '/api/tuning'): 'admin',
    ('GET', '/api/brain/upgrade'): 'viewer',
    ('GET', '/api/brain/ha'): 'viewer',
    ('POST', '/api/brain/sensors/{sensor_id}/segment'): 'admin',
    ('POST', '/api/brain/segments/{segment}/commands'): 'operator',
    ('POST', '/api/brain/upgrade'): 'admin',
    ('POST', '/api/brain/upgrade/clear'): 'admin',
    ('GET', '/api/fleet'): 'viewer',
    ('GET', '/api/fleet/sites/{site_id}/history'): 'viewer',
    ('POST', '/api/fleet/codes'): 'admin',
    ('POST', '/api/fleet/sites/{site_id}/revoke'): 'admin',
    ('POST', '/api/fleet/sites/{site_id}/group'): 'admin',
    ('POST', '/api/fleet/templates'): 'admin',
    ('POST', '/api/fleet/groups'): 'admin',
    ('POST', '/api/fleet/groups/{name}/rollout'): 'admin',
    ('GET', '/api/fleet/agent'): 'viewer',
    ('POST', '/api/fleet/federated'): 'admin',
    ('GET', '/api/devices/{ip}/peers'): 'viewer',
    ('POST', '/api/firewall/contain'): 'operator',
    ('GET', '/api/ot/segmentation'): 'viewer',
    ('POST', '/api/ot/segmentation'): 'admin',
    ('POST', '/api/ot/segmentation/allow'): 'admin',
    ('POST', '/api/ot/segmentation/refresh'): 'admin',
    ('GET', '/api/firewall/restrictions'): 'viewer',
    ('GET', '/api/playbook/pending'): 'viewer',
    ('GET', '/api/policy'): 'viewer',
    ('POST', '/api/firewall/quarantine'): 'operator',
    ('POST', '/api/firewall/ratelimit'): 'operator',
    ('POST', '/api/firewall/release'): 'operator',
    ('POST', '/api/playbook/pending/{pending_id}/approve'): 'operator',
    ('POST', '/api/playbook/pending/{pending_id}/deny'): 'operator',
    ('POST', '/api/policy/diff'): 'admin',
    ('POST', '/api/policy/apply'): 'admin',
    ('POST', '/api/alerts/feedback'): 'analyst',
    ('GET', '/api/alerts/feedback'): 'viewer',
    ('GET', '/api/models'): 'viewer',
    ('POST', '/api/models/{name}/{version}/stage'): 'admin',
    ('POST', '/api/models/{name}/rollback'): 'admin',
    ('GET', '/api/eval/latest'): 'viewer',
    ('GET', '/api/integrations'): 'admin',
    ('PUT', '/api/integrations'): 'admin',
    ('POST', '/api/integrations/test'): 'admin',
    ('GET', '/api/intel'): 'viewer',
    ('POST', '/api/intel/import'): 'admin',
    ('POST', '/api/intel/feeds'): 'admin',
    ('POST', '/api/intel/update'): 'admin',
    ('GET', '/api/reports/summary'): 'viewer',
    ('GET', '/api/devices/{ip}/history'): 'viewer',
    ('GET', '/api/export/compliance'): 'admin',
}
PROTECTED = sorted(k for k, v in ROUTES.items() if v != 'public')
USERS = {'viewer': 'vera', 'analyst': 'anna', 'operator': 'otto', 'admin': 'adam'}


def app_routes():
    out = set()
    for route in api.app.routes:
        if isinstance(route, APIRoute):
            out.update((m, route.path) for m in route.methods - {'HEAD'})
    return out


def declared_minimum(route):
    """The minimum role from the require_role() guard wired to the route, if any."""
    found = []

    def walk(dependant):
        for dep in dependant.dependencies:
            call = dep.call
            if getattr(call, '__qualname__', '') == 'require_role.<locals>.dependency':
                cells = dict(zip(call.__code__.co_freevars, (c.cell_contents for c in call.__closure__)))
                found.append(cells['minimum'])
            walk(dep)

    walk(route.dependant)
    return max(found, key=auth.ROLE_RANK.get) if found else None


def concrete(path):
    return path.replace('{ip}', '192.0.2.1').replace('{name}', 'nomodel').replace('{version}', '1').replace('{pending_id}', '0').replace('{sensor_id}', 'sensor-0').replace('{device_id}', 'dev1').replace('{username}', 'nobody').replace('{token_id}', 'nope').replace('{site_id}', 'site-0').replace('{segment}', 'seg-0').replace('{pack}', 'nis2')


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    monkeypatch.setenv('SENTINEL_MFA_ROLES', '')
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle(1000, 60))
    yield
    auth.get_store().close()


@pytest.fixture
def headers():
    store = auth.get_store()
    c = TestClient(api.app)
    out = {}
    for role, name in USERS.items():
        store.create_user(name, PASSWORD, role)
        token = c.post('/api/auth/login', json={'username': name, 'password': PASSWORD}).json()['access_token']
        out[role] = {'Authorization': f'Bearer {token}'}
    return out


def test_every_route_is_listed():
    assert app_routes() == set(ROUTES), 'add new routes to ROUTES with their minimum role'


@pytest.mark.parametrize('method, path', sorted(ROUTES))
def test_declared_role_matches_the_route_guard(method, path):
    route = next(r for r in api.app.routes
                 if isinstance(r, APIRoute) and r.path == path and method in r.methods)
    expected = ROUTES[(method, path)]
    assert declared_minimum(route) == (None if expected == 'public' else expected)


@pytest.mark.parametrize('method, path', PROTECTED)
def test_anonymous_is_refused(method, path):
    r = TestClient(api.app).request(method, concrete(path), json={})
    assert r.status_code == 401, r.text


@pytest.mark.parametrize('method, path', [k for k in PROTECTED if ROUTES[k] != 'viewer'])
def test_role_below_minimum_is_refused(method, path, headers):
    minimum = ROUTES[(method, path)]
    below = auth.ROLES[auth.ROLE_RANK[minimum] - 1]
    r = TestClient(api.app).request(method, concrete(path), json={}, headers=headers[below])
    assert r.status_code == 403, f'{below} reached {method} {path}: {r.status_code}'


@pytest.mark.parametrize('method, path', [k for k in PROTECTED if k[0] == 'GET'])
def test_minimum_role_is_allowed_on_reads(method, path, headers):
    r = TestClient(api.app).request(method, concrete(path), headers=headers[ROUTES[(method, path)]])
    assert r.status_code not in (401, 403), f'{method} {path}: {r.status_code} {r.text[:200]}'
