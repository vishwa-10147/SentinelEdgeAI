"""Compliance packs: framework controls mapped to the evidence this appliance can supply (Phase 7).

Documentation support, not certification. Controls are identified by their
reference in the framework; the descriptions are short summaries in our own
words (read the standards themselves for the requirements). A control with no
mapped evidence is organisational ("manual"): the appliance cannot show it.
"""

PACKS = {
    'iso27001': {
        'title': 'ISO/IEC 27001:2022 (Annex A)',
        'scope': 'Technical controls a network detection and response appliance can evidence.',
        'controls': [
            ('A.5.1', 'Information security policies are defined and approved', []),
            ('A.5.7', 'Threat intelligence is collected and analysed', ['threat_intel']),
            ('A.5.9', 'Information and associated assets are inventoried', ['asset_inventory', 'ot_assets']),
            ('A.5.15', 'Access to information and systems follows rules', ['rbac']),
            ('A.5.17', 'Authentication information is managed securely', ['mfa']),
            ('A.5.24', 'Incident management is planned and prepared', ['incident_response']),
            ('A.5.25', 'Security events are assessed and classified', ['detection', 'incident_response']),
            ('A.5.26', 'Incidents are responded to', ['incident_response', 'segmentation']),
            ('A.5.28', 'Evidence of events is collected and preserved', ['audit_log']),
            ('A.5.30', 'ICT is ready for business continuity', ['backup', 'ha']),
            ('A.6.3', 'Staff receive security awareness and training', []),
            ('A.7', 'Physical security of premises and equipment', []),
            ('A.8.2', 'Privileged access is restricted and managed', ['rbac', 'mfa']),
            ('A.8.5', 'Authentication is secure', ['mfa', 'tls']),
            ('A.8.7', 'Systems are protected against malware', ['detection']),
            ('A.8.8', 'Technical vulnerabilities are managed', ['secure_updates']),
            ('A.8.13', 'Information is backed up and backups are tested', ['backup']),
            ('A.8.15', 'Activities and events are logged', ['audit_log', 'siem']),
            ('A.8.16', 'Networks and systems are monitored for anomalous behaviour', ['monitoring', 'detection']),
            ('A.8.20', 'Networks are secured and controlled', ['monitoring', 'segmentation']),
            ('A.8.22', 'Networks are segregated', ['segmentation']),
            ('A.8.24', 'Cryptography is used effectively', ['tls', 'link_auth']),
            ('A.8.32', 'Changes are controlled', ['policy_history']),
        ],
    },
    'iec62443': {
        'title': 'IEC 62443-3-3 (system security requirements)',
        'scope': 'Requirements for an industrial control system that the appliance helps meet at the network level.',
        'controls': [
            ('SR 1.1', 'Human users are identified and authenticated', ['rbac', 'mfa']),
            ('SR 1.2', 'Software processes and devices are identified and authenticated', ['link_auth']),
            ('SR 1.5', 'Authenticators are managed', ['mfa']),
            ('SR 2.1', 'Authorisation is enforced', ['rbac']),
            ('SR 2.8', 'Security-relevant events are auditable', ['audit_log']),
            ('SR 2.9', 'Audit storage is sufficient and protected', ['audit_log', 'siem']),
            ('SR 3.1', 'Communication integrity is protected', ['tls', 'link_auth']),
            ('SR 3.2', 'Malicious code is detected and its effects limited', ['detection', 'incident_response']),
            ('SR 3.3', 'Security functions are verified', ['secure_updates', 'detection']),
            ('SR 5.1', 'The network is segmented into zones', ['segmentation', 'ot_assets']),
            ('SR 5.2', 'Zone boundaries are protected', ['segmentation', 'incident_response']),
            ('SR 6.1', 'Audit logs are accessible to authorised people and tools', ['audit_log', 'siem']),
            ('SR 6.2', 'The control system is continuously monitored', ['monitoring', 'ot_assets']),
            ('SR 7.1', 'Denial of service is withstood', ['incident_response']),
            ('SR 7.3', 'Control system data is backed up', ['backup']),
            ('SR 7.6', 'Network and security settings are configured and controlled', ['policy_history']),
            ('SR 7.8', 'Control system components are inventoried', ['asset_inventory', 'ot_assets']),
            ('ZCR', 'Zones and conduits are defined by a risk assessment', []),
        ],
    },
    'nis2': {
        'title': 'NIS2 Directive (EU) 2022/2555, Article 21(2) and Article 23',
        'scope': 'Cybersecurity risk-management measures and incident reporting the appliance supports.',
        'controls': [
            ('21(2)(a)', 'Policies on risk analysis and information system security', ['policy_history']),
            ('21(2)(b)', 'Incident handling', ['detection', 'incident_response', 'siem']),
            ('21(2)(c)', 'Business continuity, backup management and disaster recovery', ['backup', 'ha']),
            ('21(2)(d)', 'Supply chain security', ['secure_updates']),
            ('21(2)(e)', 'Security in acquisition, development and maintenance, incl. vulnerability handling',
             ['secure_updates']),
            ('21(2)(f)', 'Assessing the effectiveness of risk-management measures', ['detection', 'audit_log']),
            ('21(2)(g)', 'Basic cyber hygiene and cybersecurity training', []),
            ('21(2)(h)', 'Cryptography and, where appropriate, encryption', ['tls', 'link_auth']),
            ('21(2)(i)', 'Human resources security, access control and asset management', ['rbac', 'asset_inventory']),
            ('21(2)(j)', 'Multi-factor authentication and secured communications', ['mfa', 'tls']),
            ('23', 'Significant incidents are reported within the deadlines (early warning within 24 h)',
             ['siem', 'reporting']),
        ],
    },
}

RANK = {'gap': 0, 'partial': 1, 'met': 2}


def control_status(evidence, keys):
    """Combine a control's evidence: manual without evidence; met only if every applicable item is met."""
    if not keys:
        return 'manual'
    statuses = [evidence[k]['status'] for k in keys if evidence[k]['status'] != 'n/a']
    if not statuses:
        return 'n/a'
    if all(s == 'met' for s in statuses):
        return 'met'
    if all(s == 'gap' for s in statuses):
        return 'gap'
    return 'partial'


def report(pack, evidence=None):
    from compliance import evidence as ev
    import time
    if pack not in PACKS:
        raise ValueError(f'unknown pack: {pack} (one of {", ".join(PACKS)})')
    p = PACKS[pack]
    keys = sorted({k for _, _, ks in p['controls'] for k in ks})
    evidence = evidence or ev.collect(keys)
    controls, totals = [], {'met': 0, 'partial': 0, 'gap': 0, 'manual': 0, 'n/a': 0}
    for ref, title, ks in p['controls']:
        status = control_status(evidence, ks)
        totals[status] += 1
        controls.append({'id': ref, 'title': title, 'status': status,
                         'evidence': [{'key': k, **evidence[k]} for k in ks]})
    return {'pack': pack, 'title': p['title'], 'scope': p['scope'], 'generated': int(time.time()),
            'disclaimer': 'Documentation support only: this report lists technical evidence from one SentinelEdgeAI '
                          'appliance. It is not a certification or an audit opinion, and organisational controls '
                          '(marked manual) need evidence from elsewhere.',
            'totals': totals, 'controls': controls}
