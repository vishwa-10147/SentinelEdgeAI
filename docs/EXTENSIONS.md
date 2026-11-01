# Writing and installing extensions

Extensions add detectors (and response-action hooks) without changing the appliance. They are signed by
their publisher, installed only from publishers an Admin trusts, and run in a sandbox.

## For publishers

```bash
python -m extensions keygen ~/publisher.key          # once; keep the private key offline
cp -r examples/extensions/default-c2-ports my-ext    # start from the example
# edit my-ext/manifest.json and my-ext/main.py
python -m extensions sign my-ext --key ~/publisher.key
python -m extensions pack my-ext my-ext-1.0.0.tar.gz # give this and publisher.key.pub to users
```

`manifest.json`: `name` (lowercase, dashes), `version` (x.y.z), `publisher`, `kind` (`detector` or `action`),
`entry` (a `.py` file at the top), `events` (`flow`, `dns`, `http` for detectors; `action` for action
extensions), `network` (default false), `memory_mb` (32-1024), `description`.

The code may use the Python standard library and `sentinel_sdk` (see `extensions/sdk/sentinel_sdk.py`):

```python
from sentinel_sdk import Finding, run

def on_flow(flow):   # src, dst, sport, dport, proto, duration, forward/backward bytes and packets, ts
    if flow['dport'] == 4444:
        return [Finding('metasploit_port', flow['src'], 70, 0.6, 'T1571', 'default Metasploit port')]

run(on_flow=on_flow)   # also on_dns, on_http, on_action
```

## For Admins

```bash
python -m extensions trust "Example Co" publisher.key.pub    # pin the publisher key
python -m extensions install my-ext-1.0.0.tar.gz             # verified; starts disabled
python -m extensions test my-ext                             # run it once in its sandbox
python -m extensions enable my-ext                           # then restart the engine
python -m extensions list | disable my-ext | remove my-ext
```

An extension that asks for network access is refused unless installed with `--allow-network`.

## What an extension can and cannot do

| | |
|---|---|
| **Signature** | Ed25519 over the manifest and the SHA-256 of every file; checked at install and again every time it is enabled or started. A changed file stops it. |
| **Network** | None (its own empty network namespace), unless the manifest asks and the Admin allowed it. |
| **Files** | The appliance's data, configuration, logs, reports and model directories, `/etc/sentinel`, `/var/lib/sentinel`, `/root`, `~/.ssh` and the release key directory are covered by empty read-only mounts; its own directory is read-only; `/tmp` is private; it cannot write files (file-size limit 0). |
| **Privileges** | Its own user namespace with the service's uid, no capabilities after start, no new privileges; it cannot undo the mounts. |
| **Resources** | Memory (`memory_mb`), CPU priority lowered, 32 open files, no core dumps; an empty environment. |
| **Findings** | Only about a device in the event it answers; kind `ext:<name>:<kind>`; severity at most 80, probability at most 0.7; never an automatic response on its own (fusion needs a second, independent signal). |
| **Failures** | The engine never waits for it (events are dropped when it falls behind). 3 crashes or 20 malformed answers disable it, and it is audited. If the sandbox cannot be built on a system, the extension does not run. |
| **Actions** | Action extensions are told about responses the playbook applied (action, device, reason). They cannot apply responses themselves; anything that acts must use a scoped API token through the normal endpoints, policy and approvals. |

Tested against a hostile extension that tries to reach the network, read the data directory, write
files, undo the mounts and report a device not in its event: all refused (`tests/test_extensions.py`).
