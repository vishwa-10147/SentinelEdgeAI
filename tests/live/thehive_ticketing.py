"""Incident -> TheHive 5 alert, then update and resolve, through integrations.ticketing (run by run_thehive.sh)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
os.environ['SENTINEL_TICKETS'] = os.path.join(tempfile.mkdtemp(), 'tickets.json')
import requests  # noqa: E402
from integrations import ticketing  # noqa: E402

HIVE = sys.argv[1]
ADMIN = ('admin@thehive.local', 'secret')
s = requests.Session()
s.auth = ADMIN
org = 'sentinel-lab'
if s.get(f'{HIVE}/api/v1/organisation/{org}').status_code == 404:
    s.post(f'{HIVE}/api/v1/organisation', json={'name': org, 'description': 'SentinelEdgeAI live test'}).raise_for_status()
login = 'soar@sentinel.lab'
user = s.get(f'{HIVE}/api/v1/user/{login}')
if user.status_code == 404:
    s.post(f'{HIVE}/api/v1/user', json={'login': login, 'name': 'SentinelEdgeAI', 'organisation': org,
                                        'profile': 'analyst'}).raise_for_status()
key = s.post(f'{HIVE}/api/v1/user/{login}/key/renew').text.strip()
target = ticketing.build({'type': 'thehive', 'name': 'hive', 'url': HIVE, 'api_token': key, 'organisation': org,
                          'allow_http': True, 'min_severity': 'high'})
now = time.time()
inc = {'id': f'inc-{int(now)}', 'title': 'Port scan and admin share use from 10.0.0.66', 'severity': 'high',
       'status': 'open', 'alert_count': 2, 'first_seen': now - 600, 'last_seen': now - 60, 'sources': ['10.0.0.66'],
       'targets': ['10.0.0.5'], 'techniques': ['T1046', 'T1021.002'], 'kinds': ['port_scan', 'admin_share'],
       'checklist': ['Ask your IT admin if this was them'], 'timeline': [], 'risk': 78}
print('sync 1', ticketing.sync([inc], [target], console_url='https://sentinel.test', now=now))
ref = ticketing.load_map()[inc['id']]['hive']
api = requests.Session()
api.headers.update({'Authorization': f'Bearer {key}', 'X-Organisation': org})
alert = api.get(f'{HIVE}/api/v1/alert/{ref["id"]}').json()
obs = api.post(f'{HIVE}/api/v1/query', json={'query': [{'_name': 'getAlert', 'idOrName': ref['id']},
                                                        {'_name': 'observables'}]}).json()
print('alert  ', alert['title'], '| severity', alert['severity'], '| sourceRef', alert['sourceRef'] == inc['id'],
      '| tags', alert['tags'], '| observables', sorted(o['data'] for o in obs))
inc['alert_count'] = 3
print('sync 2', ticketing.sync([inc], [target], now=now + 60))
inc.update(status='resolved', note='scanner of the IT team', updated_by='alice')
print('sync 3', ticketing.sync([inc], [target], now=now + 120))
desc = api.get(f'{HIVE}/api/v1/alert/{ref["id"]}').json()['description']
print('final description:', desc[:160].replace('\n', ' '))
ok = alert['sourceRef'] == inc['id'] and sorted(o['data'] for o in obs) == ['10.0.0.5', '10.0.0.66'] \
    and 'Resolved in SentinelEdgeAI by alice' in desc
print('PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
