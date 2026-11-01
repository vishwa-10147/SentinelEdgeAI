"""Example detector extension: default ports of attack frameworks (standard library + sentinel_sdk only)."""
import ipaddress

from sentinel_sdk import Finding, run

PORTS = {4444: 'Metasploit', 50050: 'Cobalt Strike team server', 31337: 'Sliver / Back Orifice'}


def internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def on_flow(flow):
    framework = PORTS.get(flow.get('dport'))
    if framework and internal(flow['src']) and not internal(flow['dst']):
        return [Finding('default_c2_port', flow['src'], 60, 0.5, 'T1571',
                        f"{flow['src']} connected to {flow['dst']}:{flow['dport']}, the default {framework} port")]


run(on_flow=on_flow)
