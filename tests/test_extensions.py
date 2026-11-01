"""Extension SDK: signed packages, trusted publishers, the sandbox, and checked findings (Phase 11)."""
import json
import os
import shutil
import time

import pytest

from common import signing
from extensions import package
from extensions.host import MAX_PROBABILITY, MAX_SEVERITY, ExtensionHost
from extensions.sandbox import available as sandbox_available

# Hosts that forbid unprivileged user namespaces (e.g. Ubuntu runners with AppArmor's userns restriction) cannot
# build the sandbox; extensions then refuse to run (tested below), and the sandbox tests are skipped.
SANDBOX = sandbox_available()
needs_sandbox = pytest.mark.skipif(not SANDBOX, reason='unprivileged user namespaces are not available here')

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
EXAMPLE = os.path.join(ROOT, 'examples', 'extensions', 'default-c2-ports')
FLOW = {'src': '10.0.0.66', 'dst': '45.77.10.20', 'sport': 50000, 'dport': 4444, 'proto': 'TCP', 'duration': 1.0,
        'forward_bytes': 400, 'backward_bytes': 900, 'ts': 1_800_000_000.0}

# A hostile extension: probes the sandbox, then tries to cheat on findings.
PROBE = r'''
import ctypes, json, os, socket
from sentinel_sdk import Finding, run
results = {}
try:
    socket.create_connection(("1.1.1.1", 53), timeout=2); results["network"] = "reachable"
except OSError as e:
    results["network"] = "blocked"
data = os.environ.get("PROBE_DATA") or "@DATA@"
results["data_listing"] = sorted(os.listdir(data)) if os.path.isdir(data) else "missing"
def write(path):
    try:
        with open(path, "w") as f:            # with: the error surfaces at close, not in a destructor
            f.write("x" * 10)
        return "ok"
    except OSError:
        return "refused"
results["write_own_dir"] = write("/tmp/extension/x")
results["write_tmp"] = write("/tmp/scratch")
libc = ctypes.CDLL(None, use_errno=True)
results["umount_hidden"] = "ok" if libc.umount2(data.encode(), 2) == 0 else "refused"
results["uid"] = os.getuid()
results["env"] = sorted(os.environ)

def on_flow(flow):
    return [Finding("probe", flow["src"], 100, 1.0, "T0000", json.dumps(results)),
            Finding("frame", "10.9.9.9", 50, 0.5, "T0000", "accusing a device that is not in the event")]

run(on_flow=on_flow)
'''


@pytest.fixture()
def publisher():
    private, public = signing.generate_keypair()
    package.trust('Test Publisher', public)
    return private, public


def make_package(tmp_path, publisher, name='default-c2-ports', code=None, manifest=None):
    d = tmp_path / name
    shutil.copytree(EXAMPLE, d)
    m = json.loads((d / 'manifest.json').read_text())
    m.update(name=name, **(manifest or {}))
    (d / 'manifest.json').write_text(json.dumps(m))
    if code is not None:
        (d / 'main.py').write_text(code)
    package.sign(str(d), *publisher)
    return d


def run_flow(name, rounds=20):
    host = ExtensionHost(names=[name])
    assert host.wait_ready(15)[name], host.status()
    findings = []
    for _ in range(rounds):
        findings += host.flow(dict(FLOW, ts=time.time()))
        if findings:
            break
        time.sleep(0.2)
    return host, findings


def test_signed_install_and_refusals(tmp_path, publisher):
    d = make_package(tmp_path, publisher)
    m = package.install(str(d))
    assert m['name'] == 'default-c2-ports' and package.load_state()[m['name']]['enabled'] is False
    # unsigned / tampered / untrusted publisher
    (d / 'main.py').write_text((d / 'main.py').read_text() + '\n# changed\n')
    with pytest.raises(package.ExtensionError, match='do not match'):
        package.install(str(d))
    other = signing.generate_keypair()
    e = make_package(tmp_path / 'x', other, name='untrusted-one')
    with pytest.raises(package.ExtensionError, match='untrusted key'):
        package.install(str(e))
    net = make_package(tmp_path / 'n', publisher, name='needs-network', manifest={'network': True})
    with pytest.raises(package.ExtensionError, match='allow-network'):
        package.install(str(net))
    assert package.install(str(net), allow_network=True)['network'] is True
    # a file changed on disk after installation stops it from being enabled
    installed = package.installed_dir('default-c2-ports')
    os.chmod(installed, 0o750)
    os.chmod(os.path.join(installed, 'main.py'), 0o640)
    with open(os.path.join(installed, 'main.py'), 'a') as f:
        f.write('\n# tampered after install\n')
    with pytest.raises(package.ExtensionError, match='do not match'):
        package.set_enabled('default-c2-ports', True)


def test_packed_archive_round_trip(tmp_path, publisher):
    d = make_package(tmp_path, publisher)
    archive = package.pack(str(d), str(tmp_path / 'ext.tar.gz'))
    assert package.install(archive)['version'] == '1.0.0'


@needs_sandbox
def test_example_runs_in_the_sandbox(tmp_path, publisher):
    package.install(str(make_package(tmp_path, publisher)))
    host, findings = run_flow('default-c2-ports')
    host.stop()
    [f] = findings
    assert f.kind == 'ext:default-c2-ports:default_c2_port' and f.src == '10.0.0.66' and 'Metasploit' in f.evidence


@needs_sandbox
def test_sandbox_contains_a_hostile_extension(tmp_path, publisher):
    data_dir = os.path.join(ROOT, 'data')
    os.makedirs(data_dir, exist_ok=True)
    package.install(str(make_package(tmp_path, publisher, name='probe', code=PROBE.replace('@DATA@', data_dir))))
    host, findings = run_flow('probe')
    status = host.status()['probe']
    host.stop()
    [f] = findings                                       # the finding about 10.9.9.9 was dropped
    assert f.severity == MAX_SEVERITY and f.probability == MAX_PROBABILITY
    seen = json.loads(f.evidence.split('] ', 1)[1])
    assert seen['network'] == 'blocked'
    assert seen['data_listing'] == []                    # the appliance's data directory is an empty cover
    assert seen['write_own_dir'] == 'refused' and seen['write_tmp'] == 'refused'
    assert seen['umount_hidden'] == 'refused'            # no capabilities after exec
    assert seen['uid'] == os.getuid()
    assert 'SENTINEL_EXTENSION' in seen['env'] and not any(k.startswith('SENTINEL_AUTH') for k in seen['env'])
    assert status['bad'] >= 1


@needs_sandbox
def test_crashing_extension_is_disabled(tmp_path, publisher, monkeypatch):
    import extensions.host as h
    import types
    monkeypatch.setattr(h, 'time', types.SimpleNamespace(sleep=lambda s: None, time=time.time))   # no restart back-off
    package.install(str(make_package(tmp_path, publisher, name='crasher', code='raise SystemExit(3)\n')))
    package.set_enabled('crasher', True)
    host = ExtensionHost(names=['crasher'])
    for _ in range(100):
        if host.status()['crasher']['disabled']:
            break
        time.sleep(0.1)
    assert host.status()['crasher']['crashes'] == 3, host.status()
    assert package.load_state()['crasher']['enabled'] is False
    assert 'status 3' in package.load_state()['crasher']['disabled_reason']
    host.stop()


@needs_sandbox
def test_findings_join_the_pipeline_without_auto_response(tmp_path, publisher):
    from detection.pipeline import DetectionPipeline
    package.install(str(make_package(tmp_path, publisher)))
    host = ExtensionHost(names=['default-c2-ports'])
    host.wait_ready(15)
    pipe = DetectionPipeline(models=False, extensions=host, flow_detectors=[])
    kinds = []
    for _ in range(20):
        fused = pipe.observe_flow(dict(FLOW, ts=time.time()))
        kinds += [f['kind'] for f in fused['new_findings']]
        if kinds:
            break
        time.sleep(0.2)
    host.stop()
    assert kinds == ['ext:default-c2-ports:default_c2_port'] and fused['confirmed'] is False


@pytest.mark.skipif(SANDBOX, reason='this host can build the sandbox')
def test_without_a_sandbox_the_extension_never_runs(tmp_path, publisher):
    package.install(str(make_package(tmp_path, publisher)))
    package.set_enabled('default-c2-ports', True)
    host = ExtensionHost(names=['default-c2-ports'])
    for _ in range(100):
        if host.status()['default-c2-ports']['disabled']:
            break
        time.sleep(0.1)
    assert 'sandbox could not be created' in host.status()['default-c2-ports']['disabled']
    assert host.flow(dict(FLOW)) == []
    host.stop()
