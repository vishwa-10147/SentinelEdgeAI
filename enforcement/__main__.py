"""python -m enforcement policy export|validate|diff|apply | protected | devices | quarantine | release | pending | approve | deny | segment"""
import argparse
import json
import sys

import core.firewall as firewall
from enforcement import identity, playbook, policy, protected, segmentation


def _show(obj):
    print(json.dumps(obj, indent=2, default=str))


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m enforcement', description='SentinelEdgeAI enforcement tools.')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('policy', help='response policy as code')
    p.add_argument('action', choices=['export', 'validate', 'diff', 'apply'])
    p.add_argument('file', nargs='?')
    p.add_argument('--by', default='cli')
    sub.add_parser('protected', help='hosts that are never blocked, and why')
    sub.add_parser('devices', help='known devices by MAC (refreshes from the ARP table)')
    for name in ('quarantine', 'ratelimit'):
        p = sub.add_parser(name, help=f'{name} an IP')
        p.add_argument('ip')
        p.add_argument('--ttl', type=int)
        p.add_argument('--reason', default='operator')
    p = sub.add_parser('release', help='remove a quarantine or rate limit')
    p.add_argument('kind', choices=['quarantine', 'ratelimit'])
    p.add_argument('ip')
    sub.add_parser('pending', help='playbook actions waiting for approval')
    for name in ('approve', 'deny'):
        p = sub.add_parser(name, help=f'{name} a pending playbook action')
        p.add_argument('id', type=int)
        p.add_argument('--by', default='cli')
    p = sub.add_parser('segment', help='OT micro-segmentation from learned allow-lists')
    p.add_argument('action', choices=['status', 'off', 'monitor', 'enforce', 'allow', 'refresh'])
    p.add_argument('args', nargs='*', help='allow: SRC DST PROTOCOL')
    p.add_argument('--by', default='cli')
    args = parser.parse_args(argv)

    try:
        if args.command == 'segment':
            if args.action == 'status':
                _show(segmentation.status())
            elif args.action == 'allow':
                if len(args.args) != 3:
                    print('allow needs SRC DST PROTOCOL', file=sys.stderr)
                    return 2
                _show(segmentation.allow(*args.args, by=args.by))
            elif args.action == 'refresh':
                _show(segmentation.refresh(by=args.by))
            else:
                _show(segmentation.set_mode(args.action, by=args.by))
            return 0
        if args.command == 'policy':
            if args.action == 'export':
                print(policy.export(), end='')
                return 0
            if not args.file:
                print('a policy file is required', file=sys.stderr)
                return 2
            with open(args.file, 'r', encoding='utf-8') as f:
                doc = policy.parse(f.read())
            new, errors, warnings = policy.validate(doc)
            for w in warnings:
                print(f'warning: {w}')
            if errors:
                for e in errors:
                    print(f'error: {e}', file=sys.stderr)
                return 1
            if args.action == 'validate':
                print('policy is valid')
            elif args.action == 'diff':
                changes = policy.diff(new)
                if not changes:
                    print('no changes')
                for key, old, value in changes:
                    print(f'- {key}: {json.dumps(old, default=str)}\n+ {key}: {json.dumps(value, default=str)}')
            else:
                result = policy.apply(doc, by=args.by)
                print(f"applied; changed: {', '.join(c[0] for c in result['changes']) or 'nothing'}")
            return 0
        if args.command == 'protected':
            _show(protected.summary())
        elif args.command == 'devices':
            reg = identity.get_registry()
            reg.refresh_from_arp()
            for d in reg.list():
                print(f"{d['mac']}  {d['ip'] or '-':<16} {(d['vendor'] or '?')[:28]:<28} {d['hostname'] or ''}")
        elif args.command in ('quarantine', 'ratelimit'):
            _show(firewall.add_restriction(args.command, args.ip, ttl=args.ttl, reason=args.reason))
        elif args.command == 'release':
            _show(firewall.remove_restriction(args.kind, args.ip))
        elif args.command == 'pending':
            _show(playbook.get_playbook().pending())
        elif args.command in ('approve', 'deny'):
            _show(playbook.get_playbook().decide(args.id, args.command == 'approve', args.by))
    except KeyError as exc:
        print(f'not found: {exc.args[0]}', file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
