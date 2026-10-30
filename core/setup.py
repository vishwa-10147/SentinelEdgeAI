"""First-run device setup: network role, placement, capture interface, response mode.

Settings live in data/setup.json (SENTINEL_SETUP_FILE), written by an admin
through the console's setup wizard. The engine reads the capture interface
at start and restarts itself when it changes.
"""
import json
import os
import re
import tempfile
import time

import psutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

ROLES = {
    'standalone': {'label': 'Standalone', 'available': True,
                   'help': 'This device captures, detects, enforces and runs the console (Lite profile).'},
    'sensor': {'label': 'Sensor', 'available': True,
               'help': 'Captures, detects locally and enforces; sends flows to a Brain and executes its '
                       'signed commands. Enrol it with a code from the Brain after setup.'},
    'brain': {'label': 'Brain', 'available': True,
              'help': 'Receives flows from sensors over mutual TLS, runs the console and sends signed '
                      'commands (Jetson in the Standard profile; any device can act as one).'},
}
PLACEMENTS = {
    'passive': {'label': 'Passive (mirror port)',
                'help': 'A switch mirrors traffic to this device. No risk to the network; it alerts but '
                        'cannot block traffic that does not pass through it.'},
    'inline': {'label': 'Inline (bridge)',
               'help': 'Traffic passes through this device between two network ports, so it can block. '
                       'Needs two network interfaces; bridge-level filtering arrives in v1.4, until then '
                       'blocks apply to traffic to and routed through the device.'},
}
RESPONSE_MODES = {
    'monitor': 'Record detections only.',
    'alert': 'Record detections and raise alerts.',
    'auto_block': 'Block sources automatically above the risk threshold (needs enforcement turned on).',
}
DEFAULTS = {
    'network_role': 'standalone',
    'placement': 'passive',
    'capture_interface': 'auto',
    'response_mode': 'monitor',
}
# virtual interfaces that never carry the traffic to watch
_SKIP_IFACE = re.compile(r'^(lo|docker\d*|br-[0-9a-f]+|veth\w*|virbr\d*|tun\d*|tap\d*|wg\d*)$')


def setup_file():
    return os.environ.get('SENTINEL_SETUP_FILE') or os.path.join(ROOT, 'data', 'setup.json')


def load():
    """Current settings, with defaults filled in. `completed` is False until the wizard is finished."""
    try:
        with open(setup_file(), 'r', encoding='utf-8') as f:
            stored = json.load(f)
    except (OSError, ValueError):
        stored = {}
    settings = {**DEFAULTS, 'completed': False, 'completed_at': None, 'completed_by': None}
    settings.update({k: v for k, v in stored.items() if k in settings})
    return settings


def is_complete():
    return bool(load().get('completed'))


def list_interfaces():
    """Physical-looking interfaces with their state and IPv4 addresses."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    out = []
    for name in sorted(stats):
        if _SKIP_IFACE.match(name):
            continue
        st = stats[name]
        out.append({
            'name': name,
            'up': bool(st.isup),
            'speed_mbps': st.speed or None,
            'addresses': [a.address for a in addrs.get(name, []) if a.family == 2],
        })
    return out


def validate(values):
    """Return a clean settings dict or raise ValueError."""
    role = str(values.get('network_role', DEFAULTS['network_role']))
    if role not in ROLES:
        raise ValueError('network_role must be one of: ' + ', '.join(ROLES))
    if not ROLES[role]['available']:
        raise ValueError(f"the {ROLES[role]['label']} role is not available yet")
    placement = str(values.get('placement', DEFAULTS['placement']))
    if placement not in PLACEMENTS:
        raise ValueError('placement must be passive or inline')
    iface = str(values.get('capture_interface', 'auto') or 'auto')
    if iface != 'auto' and iface not in {i['name'] for i in list_interfaces()}:
        raise ValueError(f'unknown capture interface: {iface}')
    mode = str(values.get('response_mode', DEFAULTS['response_mode']))
    if mode not in RESPONSE_MODES:
        raise ValueError('response_mode must be monitor, alert or auto_block')
    return {'network_role': role, 'placement': placement, 'capture_interface': iface, 'response_mode': mode}


def brain_marker():
    # a systemd path unit starts the brain service when this file exists
    return os.path.join(os.path.dirname(os.path.abspath(setup_file())), 'brain', 'enabled')


def save(values, by):
    """Validate and store settings, marking setup complete. Returns the stored settings."""
    settings = {**validate(values), 'completed': True, 'completed_at': int(time.time()), 'completed_by': str(by)}
    marker = brain_marker()
    if settings['network_role'] == 'brain':
        os.makedirs(os.path.dirname(marker), mode=0o700, exist_ok=True)
        open(marker, 'a').close()
    elif os.path.exists(marker):
        os.remove(marker)
    path = setup_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix='.setup-')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    return settings


def capture_interface():
    """Interface the engine should sniff on, or None for the system default."""
    iface = os.environ.get('CAPTURE_IFACE') or load().get('capture_interface')
    return None if not iface or iface == 'auto' else iface


def options():
    return {
        'roles': [{'value': k, **v} for k, v in ROLES.items()],
        'placements': [{'value': k, **v} for k, v in PLACEMENTS.items()],
        'response_modes': [{'value': k, 'help': v} for k, v in RESPONSE_MODES.items()],
    }
