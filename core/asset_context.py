"""Asset context (Phase 9).

Device criticality and offline CVE matching. Criticality is set per device
by an Admin and persisted alongside the device registry. CVE matching is
offline: a small bundled CVE list is matched against device type / OS
fingerprint (no network, no vendor cloud).

    python -m asset_context set-critical 10.0.0.5 critical
    python -m asset_context cves 10.0.0.5
"""
import json
import os
from typing import Optional

from core.storage import get_storage

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ASSETS_FILE = os.path.join(ROOT, 'data', 'asset_context.json')

# Small offline CVE list matched by keyword against device type/OS fingerprint.
# In production this would be replaced by a proper SBOM/VEX feed.
CVE_DB = [
    {'id': 'CVE-2023-23397', 'severity': 'Critical', 'cvss': 9.8,
     'keywords': ['microsoft', 'outlook', 'exchange'],
     'summary': 'Outlook elevation of privilege via MAPI'},
    {'id': 'CVE-2021-44228', 'severity': 'Critical', 'cvss': 10.0,
     'keywords': ['log4j', 'java', 'apache'],
     'summary': 'Log4Shell remote code execution'},
    {'id': 'CVE-2020-0601', 'severity': 'Critical', 'cvss': 8.1,
     'keywords': ['windows', 'cryptoapi'],
     'summary': 'Windows CryptoAPI spoofing'},
    {'id': 'CVE-2017-0144', 'severity': 'Critical', 'cvss': 9.3,
     'keywords': ['windows', 'smb'],
     'summary': 'SMBv1 remote code execution (EternalBlue)'},
    {'id': 'CVE-2022-22965', 'severity': 'Critical', 'cvss': 9.8,
     'keywords': ['spring', 'java', 'spring4shell'],
     'summary': 'Spring4Shell remote code execution'},
    {'id': 'CVE-2021-36934', 'severity': 'High', 'cvss': 7.8,
     'keywords': ['windows'],
     'summary': 'Windows SAM file elevation of privilege'},
    {'id': 'CVE-2020-1472', 'severity': 'High', 'cvss': 8.8,
     'keywords': ['windows', 'netlogon'],
     'summary': 'NetLogon elevation of privilege (Zerologon)'},
    {'id': 'CVE-2019-0708', 'severity': 'High', 'cvss': 8.8,
     'keywords': ['windows', 'rdp'],
     'summary': 'Remote Desktop Services remote code execution (BlueKeep)'},
]


class AssetContext:
    def __init__(self, path: str = ASSETS_FILE):
        self.path = path
        self._lock = None
        self._load()

    def _load(self):
        import threading
        self._lock = threading.Lock()
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
        except (OSError, ValueError):
            self._data = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self.path)

    def get(self, ip: str) -> dict:
        with self._lock:
            return dict(self._data.get(ip, {}))

    def set_criticality(self, ip: str, level: str, by: str = 'admin'):
        """Set device criticality: critical | important | standard."""
        if level not in ('critical', 'important', 'standard'):
            raise ValueError('criticality must be critical, important, or standard')
        with self._lock:
            entry = self._data.get(ip, {})
            entry['criticality'] = level
            entry['criticality_by'] = by
            entry['criticality_at'] = int(os.times().elapsed if hasattr(os.times, 'elapsed') else 0)
            import time as _t
            entry['criticality_at'] = int(_t.time())
            self._data[ip] = entry
            self._save()

    def get_criticality(self, ip: str) -> str:
        return self.get(ip).get('criticality', 'standard')

    def cves_for(self, ip: str) -> list:
        """Match CVEs against device fingerprint keywords."""
        entry = self.get(ip)
        haystack = ' '.join(str(entry.get(k, '')) for k in
                            ('type', 'os', 'os_fingerprint', 'hostname', 'vendor')).lower()
        matches = []
        for cve in CVE_DB:
            if any(kw in haystack for kw in cve['keywords']):
                matches.append(dict(cve))
        return matches

    def all_assets(self) -> dict:
        with self._lock:
            return dict(self._data)


_asset_context: Optional[AssetContext] = None


def get_asset_context() -> AssetContext:
    global _asset_context
    if _asset_context is None:
        _asset_context = AssetContext()
    return _asset_context
