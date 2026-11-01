"""CycloneDX VEX generation for releases (scripts/vex.py)."""
import importlib.util
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
spec = importlib.util.spec_from_file_location('vex', os.path.join(ROOT, 'scripts', 'vex.py'))
vex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex)

AUDIT = {'dependencies': [
    {'name': 'lxml', 'version': '6.1.3', 'vulns': [{'id': 'GHSA-xxxx-1111', 'fix_versions': ['6.1.4'],
                                                    'aliases': ['CVE-2027-0001'], 'description': 'XXE in ...'}]},
    {'name': 'requests', 'version': '2.33.1', 'vulns': [{'id': 'PYSEC-2027-9', 'fix_versions': []}]},
    {'name': 'numpy', 'version': '2.4.2', 'vulns': []}]}
STATEMENTS = [{'id': 'GHSA-xxxx-1111', 'package': 'lxml', 'state': 'not_affected',
               'justification': 'code_not_reachable', 'detail': 'XML is parsed with resolve_entities=False'},
              {'id': 'CVE-2026-1234', 'package': 'scapy', 'version': '2.7.0', 'state': 'fixed'}]


def test_vex_merges_audit_and_reviewed_statements():
    doc = vex.build(AUDIT, STATEMENTS, '2.17.0')
    assert doc['bomFormat'] == 'CycloneDX' and doc['specVersion'] == '1.5'
    by_id = {v['id']: v for v in doc['vulnerabilities']}
    assert by_id['GHSA-xxxx-1111']['analysis'] == {'state': 'not_affected', 'justification': 'code_not_reachable',
                                                   'detail': 'XML is parsed with resolve_entities=False'}
    assert by_id['GHSA-xxxx-1111']['affects'] == [{'ref': 'pkg:pypi/lxml@6.1.3'}]
    assert by_id['GHSA-xxxx-1111']['recommendation'] == 'upgrade lxml to 6.1.4'
    assert by_id['PYSEC-2027-9']['analysis'] == {'state': 'in_triage'}           # not reviewed yet
    assert by_id['CVE-2026-1234']['analysis']['state'] == 'resolved'             # reviewed statement kept
    assert len(doc['vulnerabilities']) == 3


def test_cli_and_committed_statements(tmp_path):
    audit = tmp_path / 'audit.json'
    audit.write_text(json.dumps({'dependencies': []}))
    out = tmp_path / 'vex.json'
    assert vex.main(['--audit', str(audit), '--version', '2.17.0', '--out', str(out)]) == 0
    assert json.loads(out.read_text())['metadata']['component']['version'] == '2.17.0'
