"""Hosts that must never be blocked or quarantined.

Found automatically: the default gateways, DNS servers, DHCP servers, every
address of the appliance itself, plus loopback. Added by configuration: the
policy whitelist and management hosts (SENTINEL_MANAGEMENT_HOSTS, comma
separated IPs or CIDRs, e.g. the admin workstation's subnet).

The list is cached for a minute; the network rarely changes faster.
"""
import glob
import ipaddress
import os
import re
import socket
import struct
import threading
import time

import psutil

CACHE_SECONDS = 60
_cache = {'at': 0.0, 'hosts': None}
_lock = threading.Lock()


def _gateways_v4(route_file='/proc/net/route'):
    out = set()
    try:
        with open(route_file, 'r', encoding='ascii') as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) > 3 and parts[1] == '00000000' and int(parts[3], 16) & 0x2:
                    out.add(socket.inet_ntoa(struct.pack('<L', int(parts[2], 16))))
    except OSError:
        pass
    return out


def _gateways_v6(route_file='/proc/net/ipv6_route'):
    out = set()
    try:
        with open(route_file, 'r', encoding='ascii') as f:
            for line in f:
                parts = line.split()
                # default route: destination ::/0 with a next hop
                if len(parts) > 4 and parts[0] == '0' * 32 and parts[1] == '00' and parts[4] != '0' * 32:
                    out.add(str(ipaddress.IPv6Address(bytes.fromhex(parts[4]))))
    except OSError:
        pass
    return out


def _dns_servers(resolv='/etc/resolv.conf'):
    out = set()
    try:
        with open(resolv, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'nameserver':
                    out.add(parts[1].split('%')[0])
    except OSError:
        pass
    # systemd-resolved stub: the real upstream servers live here
    for extra in ('/run/systemd/resolve/resolv.conf',):
        if os.path.exists(extra) and extra != resolv:
            out |= _dns_servers(extra)
    return out


_LEASE_RE = re.compile(r'(?:dhcp-server-identifier|SERVER_ADDRESS=|server_identifier\s*=)\s*([0-9a-fA-F.:]+)')


def _dhcp_servers(patterns=('/var/lib/dhcp/*.leases', '/var/lib/dhclient/*.leases',
                            '/run/systemd/netif/leases/*', '/var/lib/NetworkManager/*.lease')):
    out = set()
    for pattern in patterns:
        for path in glob.glob(pattern):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for match in _LEASE_RE.finditer(f.read()):
                        out.add(match.group(1).rstrip(';'))
            except OSError:
                continue
    return out


def _own_addresses():
    out = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                out.add(a.address.split('%')[0])
    return out


def _configured(env='SENTINEL_MANAGEMENT_HOSTS'):
    hosts = {x.strip() for x in os.environ.get(env, '').split(',') if x.strip()}
    try:
        from enforcement.policy import management_hosts
        hosts |= management_hosts()
    except Exception:
        pass
    return hosts


def _policy_whitelist():
    try:
        import core.firewall as firewall
        return set(firewall.get_policy().get('whitelist', []))
    except Exception:
        return set()


def discover():
    """{reason: set of IPs/CIDRs}, freshly read."""
    return {
        'loopback': {'127.0.0.0/8', '::1'},
        'gateway': _gateways_v4() | _gateways_v6(),
        'dns': _dns_servers(),
        'dhcp': _dhcp_servers(),
        'appliance': _own_addresses(),
        'management': _configured(),
        'whitelist': _policy_whitelist(),
    }


def protected_hosts(refresh=False):
    with _lock:
        if refresh or _cache['hosts'] is None or time.time() - _cache['at'] > CACHE_SECONDS:
            _cache['hosts'] = discover()
            _cache['at'] = time.time()
        return _cache['hosts']


def why_protected(ip, hosts=None):
    """The reason `ip` is protected (e.g. 'gateway'), or None."""
    try:
        addr = ipaddress.ip_address(str(ip).split('%')[0])
    except ValueError:
        return None
    for reason, entries in (hosts or protected_hosts()).items():
        for entry in entries:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return reason
            except ValueError:
                continue
    return None


def summary():
    return {reason: sorted(entries) for reason, entries in protected_hosts(refresh=True).items()}
