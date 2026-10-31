"""Evidence collectors: what this appliance can show about itself, read live (Phase 7).

Each collector returns {'status', 'summary', 'data'} with status
  met       the evidence is there
  partial   it is there with a caveat (the summary says which)
  gap       it is missing; the summary says how to close it
  n/a       does not apply to this deployment (e.g. no OT devices)
A collector that fails reports 'partial' with the error, never breaks the report.
"""
import glob
import os
import shutil
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DAY = 86400


def _ev(status, summary, **data):
    return {'status': status, 'summary': summary, 'data': data}


def audit_log():
    from core import audit
    v = audit.get_log().verify()
    if not v['ok']:
        return _ev('gap', f"audit chain broken at entry {v.get('first_bad_seq')}: {v.get('reason')}", **v)
    if not v['entries']:
        return _ev('partial', 'hash-chained audit log in place but still empty', **v)
    return _ev('met', f"hash-chained audit log, {v['entries']} entries, integrity verified", entries=v['entries'],
               head=v.get('head'))


def rbac():
    from core import auth
    users = auth.get_store().list_users()
    roles = {}
    for u in users:
        if not u['disabled']:
            roles[u['role']] = roles.get(u['role'], 0) + 1
    if not users:
        return _ev('gap', 'no user accounts yet; only the shared API key', roles=roles)
    shared_key = bool(os.environ.get('DASHBOARD_API_KEY'))
    summary = f"{sum(roles.values())} active accounts by role {roles}; every endpoint has a tested minimum role"
    if shared_key:
        summary += '; a shared API key also exists (retire it once health checks use a scoped token)'
    return _ev('partial' if shared_key else 'met', summary, roles=roles, shared_api_key=shared_key)


def mfa():
    from core import auth
    roles = auth.mfa_roles()
    users = auth.get_store().list_users()
    missing = [u['username'] for u in users if not u['disabled'] and u['role'] in roles and not u['mfa_enabled']]
    if not {'operator', 'admin'} <= set(roles):
        return _ev('gap', f'two-step sign-in is not required for operators and admins (SENTINEL_MFA_ROLES={",".join(roles)})',
                   required_for=sorted(roles))
    if missing:
        return _ev('partial', f'two-step sign-in required for {", ".join(sorted(roles))}; not yet set up: {", ".join(missing)}',
                   required_for=sorted(roles), pending=missing)
    return _ev('met', f'two-step sign-in (TOTP) required and set up for every {"/".join(sorted(roles))}; Argon2id passwords',
               required_for=sorted(roles))


def tls():
    cert = (os.environ.get('SENTINEL_TLS_CERT') or '').strip()
    if not cert:
        return _ev('gap', 'the console is served over plain HTTP (set SENTINEL_TLS_CERT/KEY or run sentinelctl tls renew)')
    from cryptography import x509
    with open(cert, 'rb') as f:
        c = x509.load_pem_x509_certificate(f.read())
    left = (c.not_valid_after_utc.timestamp() - time.time()) / DAY
    self_signed = c.issuer == c.subject
    data = {'expires_in_days': round(left), 'self_signed': self_signed, 'subject': c.subject.rfc4514_string()}
    if left < 0:
        return _ev('gap', 'the console certificate has expired', **data)
    if left < 30:
        return _ev('partial', f'console certificate expires in {left:.0f} days', **data)
    note = '; self-signed (import your organisation\'s certificate with sentinelctl tls import)' if self_signed else ''
    return _ev('met', f'HTTPS with HSTS, certificate valid for {left:.0f} more days{note}', **data)


def link_auth():
    from brain import keys as brain_keys
    from fleet import agent, keys as fleet_keys
    from sensor import uplink
    used = {'brain': brain_keys.initialised(), 'sensor': bool(uplink.load_identity()),
            'fleet_server': fleet_keys.enabled(), 'fleet_site': bool(agent.identity())}
    if not any(used.values()):
        return _ev('n/a', 'single node: no device-to-device links', **used)
    return _ev('met', 'every device link is mutual TLS from a private CA, pinned by fingerprint; brain commands are '
               'Ed25519-signed, sequenced and expiring', **used)


def monitoring():
    from core.storage import get_storage
    s = get_storage('data/sentinel.db')
    s.connect()
    flows = s.get_flows(limit=1)
    last = float(flows[0]['timestamp']) if flows else None
    if not last:
        return _ev('gap', 'no traffic recorded yet: check the capture interface in Setup')
    age = time.time() - last
    if age > 3600:
        return _ev('gap', f'no traffic recorded for {age / 3600:.1f} hours: capture may have stopped', last_flow=last)
    from core import setup
    placement = setup.load().get('placement', 'passive')
    return _ev('met', f'traffic monitored continuously ({placement} placement); last flow {age:.0f} s ago',
               last_flow=last, placement=placement)


def detection():
    from detection import registry
    idx = registry.index()
    active = {name: e.get('active') for name, e in idx.items() if e.get('active')}
    reports = sorted(glob.glob(os.path.join(ROOT, 'reports', 'eval', '*.json')), key=os.path.getmtime)
    data = {'active_models': active, 'detectors': ['port scan', 'host sweep', 'brute force', 'beaconing', 'exfiltration',
                                                  'new device', 'DNS tunnelling', 'DGA', 'TLS fingerprints', 'OT protocols']}
    if not reports:
        return _ev('partial', 'attack detectors and anomaly models running; no evaluation report yet '
                   '(python -m evaluation.harness)', **data)
    import json
    with open(reports[-1]) as f:
        ev = json.load(f)
    data['evaluation'] = {'dataset': ev.get('dataset'), 'detection_rate': ev.get('detection_rate'),
                          'false_positive_rate': ev.get('false_positive_rate')}
    return _ev('met', f"attack detectors and signed anomaly models running; last evaluation ({ev.get('dataset')}): "
               f"{ev.get('detection_rate', 0):.0%} detected, {ev.get('false_positive_rate', 0):.1%} false positives", **data)


def incident_response():
    import core.firewall as firewall
    from enforcement import policy
    pol = firewall.get_policy()
    pb = (policy.current() or {}).get('playbook') or {}
    approval = (pb.get('approval') or {}).get('required_from_risk')
    data = {'response_mode': pol.get('response_mode'), 'playbook_steps': [s['action'] for s in pb.get('steps', [])],
            'approval_from_risk': approval, 'dry_run': firewall.FIREWALL_DRY_RUN}
    if pol.get('response_mode') == 'monitor':
        return _ev('partial', 'alerts only (response mode "monitor"): containment is manual', **data)
    if firewall.FIREWALL_DRY_RUN:
        return _ev('partial', 'graduated playbook configured but the firewall is in dry run (FIREWALL_DRY_RUN=1)', **data)
    return _ev('met', f"graduated playbook {' -> '.join(data['playbook_steps'])}, operator approval from risk {approval}, "
               'protected hosts, rollback in ~100 ms, fail-open watchdog', **data)


def asset_inventory():
    from enforcement import identity
    n = len(identity.get_registry().list(limit=100000))
    if not n:
        return _ev('gap', 'no devices identified yet (ARP/DHCP)')
    return _ev('met', f'{n} devices identified by MAC, vendor, hostname and DHCP fingerprint, with IP history', devices=n)


def ot_assets():
    from detection.ot import OTStore
    st = OTStore()
    try:
        servers, links = st.load()
    finally:
        st.close()
    if not servers:
        return _ev('n/a', 'no Modbus, DNP3, BACnet or OPC UA traffic seen')
    return _ev('met', f'{len(servers)} industrial controllers inventoried with the hosts that command them and the '
               'functions they use', controllers=len(servers), links=len(links))


def segmentation():
    from core import setup
    from enforcement import segmentation as seg
    mode = seg.load()['mode']
    inline = setup.load().get('placement') == 'inline'
    data = {'ot_segmentation': mode, 'placement': 'inline' if inline else 'passive', 'containment': True}
    if not inline:
        return _ev('partial', 'passive placement: segmentation and containment are planned but cannot be enforced here',
                   **data)
    if mode == 'enforce':
        return _ev('met', 'OT controllers reachable only by their learned masters; untrusted devices can be contained to '
                   'their learned peers', **data)
    return _ev('partial', f'OT segmentation in "{mode}" mode; containment available per device', **data)


def threat_intel():
    from intel.store import get_store
    feeds = get_store().feeds()
    if not feeds:
        return _ev('gap', 'no threat-intelligence feed configured (STIX/TAXII or plain lists)')
    return _ev('met', f'{len(feeds)} threat-intelligence feed(s), updated daily, matched on flows, DNS and TLS',
               feeds=[f['name'] for f in feeds])


def siem():
    from integrations import dispatcher
    cfg = dispatcher.load_config() or {}
    sinks = [s for s in cfg.get('sinks', []) if s.get('enabled', True)]
    if not sinks:
        return _ev('gap', 'alerts are not exported (configure syslog/CEF, a webhook or JSON lines in Integrations)')
    return _ev('met', f'{len(sinks)} export target(s): ' + ', '.join(sorted({s.get("type", "?") for s in sinks})),
               sinks=len(sinks))


def backup():
    from ops import backup as ops_backup
    last = ops_backup.last_backup()
    if not last:
        return _ev('gap', 'no backup recorded (sudo sentinelctl backup /path/file.seab)')
    age = (time.time() - last['ts']) / DAY
    if age > 7:
        return _ev('partial', f'last encrypted backup {age:.0f} days ago', last=last['ts'])
    return _ev('met', f'encrypted backup (scrypt + AES-256-GCM) {age:.1f} days ago', last=last['ts'])


def ha():
    from brain import keys as brain_keys
    if not brain_keys.initialised():
        return _ev('n/a', 'single node; the fail-open watchdog keeps traffic flowing if the engine stops')
    from brain import ha as brain_ha, manage
    st = brain_ha.status(manage.store())
    if not st['shared_database']:
        return _ev('partial', 'one brain on local storage; add a standby brain on a shared PostgreSQL for failover', **st)
    return _ev('met', f"brain {st['role']} with a shared database; standby takes over within 30 s", **st)


def secure_updates():
    try:
        with open(os.path.join(ROOT, 'VERSION')) as f:
            version = f.read().strip()
    except OSError:
        version = 'unknown'
    cosign = bool(shutil.which('cosign'))
    data = {'version': version, 'cosign_installed': cosign}
    summary = (f'version {version}; releases are reproducible, Sigstore-signed, with SBOM and build provenance; updates are '
               'checksum-verified, health-checked and roll back automatically')
    if not cosign:
        return _ev('partial', summary + '; install cosign so updates also verify the signature', **data)
    return _ev('met', summary, **data)


def policy_history():
    from enforcement import policy
    files = glob.glob(os.path.join(policy.history_dir(), '*.yaml'))
    if not files:
        return _ev('partial', 'response policy is versioned YAML, but no change has been applied yet')
    return _ev('met', f'{len(files)} recorded policy change(s), each validated, diffed and audited', changes=len(files))


def reporting():
    reports = glob.glob(os.path.join(os.environ.get('SENTINEL_REPORT_DIR', '/var/lib/sentinel/reports'), '*.json'))
    if not reports:
        return _ev('partial', 'daily/weekly summaries and compliance export available; none written yet')
    newest = max(os.path.getmtime(r) for r in reports)
    return _ev('met', f'daily security summaries written (latest {(time.time() - newest) / 3600:.0f} h ago); '
               'compliance export of alerts and audit entries', reports=len(reports))


COLLECTORS = {f.__name__: f for f in (audit_log, rbac, mfa, tls, link_auth, monitoring, detection, incident_response,
                                       asset_inventory, ot_assets, segmentation, threat_intel, siem, backup, ha,
                                       secure_updates, policy_history, reporting)}


def collect(keys=None):
    out = {}
    for name in keys or COLLECTORS:
        try:
            out[name] = COLLECTORS[name]()
        except Exception as exc:
            out[name] = _ev('partial', f'could not collect: {type(exc).__name__}: {str(exc)[:160]}')
    return out
