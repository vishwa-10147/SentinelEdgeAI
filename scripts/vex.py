#!/usr/bin/env python3
"""CycloneDX 1.5 VEX for a release: what is known about vulnerabilities in the shipped dependencies.

    pip-audit -r requirements.txt -f json -o audit.json || true
    python scripts/vex.py --audit audit.json --version 2.17.0 --out sentineledgeai-pi-2.17.0.vex.cdx.json

Every vulnerability pip-audit reports for a pinned runtime dependency appears with its analysis state:
the reviewed statement from security/vex-statements.json when there is one (for example not_affected with a
justification), otherwise `in_triage`. Reviewed statements for vulnerabilities that no longer show up are
kept too, so a published "not affected" is never silently dropped. An empty `vulnerabilities` list means
the audit found nothing on that day.
"""
import argparse
import datetime
import json
import os
import sys
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STATES = {'not_affected', 'affected', 'fixed', 'under_investigation', 'exploitable', 'in_triage', 'false_positive',
          'resolved', 'resolved_with_pedigree'}
CDX_STATE = {'affected': 'exploitable', 'fixed': 'resolved', 'under_investigation': 'in_triage'}


def _purl(name, version):
    return f'pkg:pypi/{name.lower().replace("_", "-")}@{version}'


def build(audit, statements, version, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    reviewed = {(s['id'].upper(), s['package'].lower()): s for s in statements}
    vulns, seen = [], set()
    for dep in audit.get('dependencies', []):
        for v in dep.get('vulns', []):
            key = (v['id'].upper(), dep['name'].lower())
            seen.add(key)
            s = reviewed.get(key, {})
            vulns.append(_entry(v['id'], dep['name'], dep.get('version'), s, v.get('fix_versions'),
                                v.get('description'), v.get('aliases')))
    for key, s in reviewed.items():
        if key not in seen:
            vulns.append(_entry(s['id'], s['package'], s.get('version'), s))
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'metadata': {'timestamp': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                     'component': {'type': 'application', 'name': 'SentinelEdgeAI', 'version': version,
                                   'bom-ref': f'sentineledgeai@{version}'},
                     'tools': {'components': [{'type': 'application', 'name': 'pip-audit'},
                                              {'type': 'application', 'name': 'scripts/vex.py'}]}},
        'vulnerabilities': vulns}


def _entry(vid, package, version, s, fixes=None, description=None, aliases=None):
    state = s.get('state') or 'in_triage'
    if state not in STATES:
        raise ValueError(f'{vid}: unknown state {state!r}')
    analysis = {'state': CDX_STATE.get(state, state)}
    if s.get('justification'):
        analysis['justification'] = s['justification']
    if s.get('detail'):
        analysis['detail'] = s['detail']
    entry = {'id': vid, 'source': {'name': 'OSV' if not vid.upper().startswith('CVE') else 'NVD'},
             'affects': [{'ref': _purl(package, version or 'unknown')}], 'analysis': analysis}
    if aliases:
        entry['references'] = [{'id': a, 'source': {'name': 'alias'}} for a in aliases]
    if description:
        entry['description'] = description[:1000]
    if fixes:
        entry['recommendation'] = f'upgrade {package} to {", ".join(fixes)}'
    return entry


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--audit', required=True, help='pip-audit -f json output')
    p.add_argument('--statements', default=os.path.join(ROOT, 'security', 'vex-statements.json'))
    p.add_argument('--version', required=True)
    p.add_argument('--out', required=True)
    args = p.parse_args(argv)
    with open(args.audit, encoding='utf-8') as f:
        audit = json.load(f)
    with open(args.statements, encoding='utf-8') as f:
        statements = json.load(f).get('statements', [])
    doc = build(audit, statements, args.version)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2)
    print(f"{args.out}: {len(doc['vulnerabilities'])} vulnerability statement(s)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
