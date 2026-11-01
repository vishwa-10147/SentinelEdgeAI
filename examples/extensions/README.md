# Example extensions

| Extension | Kind | What it shows |
|---|---|---|
| [`default-c2-ports`](default-c2-ports/) | detector (flow events) | Flags an internal device connecting to the default ports of attack frameworks (Metasploit, Cobalt Strike, Sliver) |

Sign, pack and install one (see [docs/EXTENSIONS.md](../../docs/EXTENSIONS.md)):

```bash
python -m extensions keygen ~/publisher.key
cp -r examples/extensions/default-c2-ports /tmp/my-ext
python -m extensions sign /tmp/my-ext --key ~/publisher.key
python -m extensions pack /tmp/my-ext /tmp/my-ext.tar.gz
python -m extensions trust "My Org" ~/publisher.key.pub && python -m extensions install /tmp/my-ext.tar.gz
python -m extensions test default-c2-ports
```
