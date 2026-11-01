"""python -m extensions keygen | sign | pack | trust | install | list | enable | disable | remove | test

Publisher:  keygen KEY  ->  sign DIR --key KEY  ->  pack DIR OUT.tar.gz
Appliance:  trust NAME PUBLISHER.pub  ->  install PKG [--allow-network]  ->  enable NAME
"""
import argparse
import json
import os
import sys

from extensions import package


def main(argv=None):
    p = argparse.ArgumentParser(prog='python -m extensions')
    sub = p.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('keygen', help='new publisher key pair (KEY and KEY.pub)')
    a.add_argument('key')
    a = sub.add_parser('sign', help='sign a package directory')
    a.add_argument('dir')
    a.add_argument('--key', required=True)
    a = sub.add_parser('pack', help='a signed directory -> .tar.gz')
    a.add_argument('dir')
    a.add_argument('out')
    a = sub.add_parser('trust', help='pin a publisher key (Admin)')
    a.add_argument('publisher')
    a.add_argument('public_key')
    a = sub.add_parser('install', help='verify and install a package (it starts disabled)')
    a.add_argument('package')
    a.add_argument('--allow-network', action='store_true')
    sub.add_parser('list', help='installed extensions and trusted publishers')
    for name in ('enable', 'disable', 'remove'):
        sub.add_parser(name).add_argument('name')
    a = sub.add_parser('test', help='run one installed extension in its sandbox on a sample flow')
    a.add_argument('name')
    args = p.parse_args(argv)
    try:
        if args.cmd == 'keygen':
            from common import signing
            private, public = signing.generate_keypair()
            fd = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(private)
            with open(args.key + '.pub', 'w') as f:
                f.write(public)
            print(json.dumps({'private_key': args.key, 'public_key': args.key + '.pub', 'kid': signing.key_id(public)}))
        elif args.cmd == 'sign':
            from cryptography.hazmat.primitives import serialization
            with open(args.key) as f:
                private = f.read()
            public = serialization.load_pem_private_key(private.encode(), None).public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            payload = package.sign(args.dir, private, public)
            print(f"signed {payload['manifest']['name']} {payload['manifest']['version']}: {len(payload['files'])} files")
        elif args.cmd == 'pack':
            print(package.pack(args.dir, args.out))
        elif args.cmd == 'trust':
            with open(args.public_key) as f:
                print(json.dumps(package.trust(args.publisher, f.read())))
        elif args.cmd == 'install':
            m = package.install(args.package, allow_network=args.allow_network)
            print(f"installed {m['name']} {m['version']} (disabled; enable with: python -m extensions enable {m['name']})")
        elif args.cmd == 'list':
            print(json.dumps({'installed': package.load_state(),
                              'trusted': {k: v['publisher'] for k, v in package.trusted_keys().items()}}, indent=2))
        elif args.cmd in ('enable', 'disable'):
            print(json.dumps(package.set_enabled(args.name, args.cmd == 'enable', reason='by an Admin' if args.cmd == 'disable' else None)))
        elif args.cmd == 'remove':
            package.remove(args.name)
            print(f'removed {args.name}')
        elif args.cmd == 'test':
            from extensions.host import ExtensionHost
            host = ExtensionHost(names=[args.name])
            print('ready:', host.wait_ready())
            import time
            rec = {'src': '10.0.0.66', 'dst': '45.77.10.20', 'sport': 50000, 'dport': 4444, 'proto': 'TCP',
                   'duration': 1.0, 'forward_bytes': 400, 'backward_bytes': 900, 'ts': time.time()}
            host.flow(rec)
            time.sleep(1)
            print(json.dumps([f.as_dict() for f in host.flow(rec)], indent=2), json.dumps(host.status()))
            host.stop()
        return 0
    except (package.ExtensionError, OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
