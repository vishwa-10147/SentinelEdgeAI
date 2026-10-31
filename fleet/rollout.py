"""Staged rollouts and desired state (pure functions, no I/O).

A group's target version reaches its sites in stages, e.g.
  [{"percent": 10, "hours": 0}, {"percent": 50, "hours": 24}, {"percent": 100, "hours": 48}]
A site belongs to the first `percent` of the fleet when a stable hash of its
id falls below it, so the same sites are always the canaries. A site that
reports a failed update pauses its group's rollout: no further site is told
to upgrade until an Admin resumes it. Sites already on the target stay there.
"""
import hashlib
import re

DEFAULT_STAGES = [{'percent': 10, 'hours': 0}, {'percent': 50, 'hours': 24}, {'percent': 100, 'hours': 48}]
VERSION = re.compile(r'^\d+\.\d+\.\d+$')


def parse_version(v):
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)', str(v or ''))
    return tuple(int(x) for x in m.groups()) if m else None


def validate_stages(stages):
    if not stages:
        return list(DEFAULT_STAGES)
    out, last_p, last_h = [], 0, -1
    for s in stages:
        p, h = int(s.get('percent', 0)), float(s.get('hours', 0))
        if not 0 < p <= 100 or p < last_p or h < last_h:
            raise ValueError('stages need increasing percent (1-100) and hours')
        out.append({'percent': p, 'hours': h})
        last_p, last_h = p, h
    if out[-1]['percent'] != 100:
        raise ValueError('the last stage must reach 100 percent')
    return out


def bucket(site_id):
    return int(hashlib.sha256(site_id.encode()).hexdigest()[:8], 16) % 100


def current_percent(group, now):
    if not group.get('target_version') or not group.get('started'):
        return 0
    percent = 0
    for s in group['stages'] or DEFAULT_STAGES:
        if now >= group['started'] + s['hours'] * 3600:
            percent = s['percent']
    return percent


def desired_version(group, site_id, site_version, now):
    """The version this site should run, or None for "stay as you are"."""
    target = group.get('target_version')
    if not target:
        return None
    have, want = parse_version(site_version), parse_version(target)
    if have and want and have >= want:
        return target                                     # already there (or newer): nothing to do
    if group.get('paused'):
        return None
    return target if bucket(site_id) < current_percent(group, now) else None


def failed_update(report, target):
    """True when the site says its update to `target` failed."""
    result = (report or {}).get('update') or {}
    return bool(target) and result.get('version') == target and result.get('ok') is False


def rollout_status(group, sites, now):
    """Summary of one group's rollout for the console."""
    target = group.get('target_version')
    members = [s for s in sites if s['grp'] == group['name'] and not s['revoked']]
    on_target = [s['id'] for s in members if target and parse_version(s.get('version')) and
                 parse_version(s['version']) >= parse_version(target)]
    return {'group': group['name'], 'target_version': target, 'percent': current_percent(group, now),
            'paused': group.get('paused'), 'sites': len(members), 'on_target': len(on_target)}
