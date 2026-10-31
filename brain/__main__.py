"""python -m brain init | code | sensors | revoke | command"""
import argparse
import json
import sys

from brain import keys, manage


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m brain', description='SentinelEdgeAI brain management.')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init', help='create the CA, server certificate and command signing key')
    p = sub.add_parser('code', help='create a one-time sensor enrolment code')
    p.add_argument('--brain-url', default='https://<brain-address>:9443')
    p.add_argument('--ttl', type=int, default=3600, help='seconds the code stays valid')
    sub.add_parser('sensors', help='list enrolled sensors')
    p = sub.add_parser('revoke', help='revoke a sensor; its certificate stops working at once')
    p.add_argument('sensor_id')
    p = sub.add_parser('command', help='send a signed command to a sensor')
    p.add_argument('sensor_id')
    p.add_argument('action', choices=['block', 'unblock', 'rollback'])
    p.add_argument('--ip')
    p.add_argument('--ttl', type=int)
    p.add_argument('--reason', default='operator')
    p = sub.add_parser('upgrade', help='stage a release for this brain\'s sensors (they download it over the link)')
    p.add_argument('action', choices=['status', 'stage', 'clear'])
    p.add_argument('--file', help='a local sentineledgeai-pi-X.Y.Z.tar.gz (its .sha256 next to it)')
    p.add_argument('--version', help='download this published release instead')
    args = parser.parse_args(argv)

    if args.command == 'init':
        created = keys.init()
        print(('created' if created else 'already initialised') + f' in {keys.brain_dir()}')
        print(f'CA fingerprint: {keys.ca_fingerprint()}')
        return 0
    if not keys.initialised():
        print('run: python -m brain init', file=sys.stderr)
        return 1
    try:
        if args.command == 'code':
            code = manage.store().create_code(args.ttl)
            print(json.dumps(manage.enrolment_instructions(code, args.brain_url), indent=2))
        elif args.command == 'sensors':
            for s in manage.store().list_sensors():
                state = 'revoked' if s['revoked'] else 'active'
                print(f"{s['id']:<18} {s['name']:<20} {state:<8} flows={s['flows']} last_seen={s['last_seen']}")
        elif args.command == 'revoke':
            manage.store().revoke_sensor(args.sensor_id)
            print(f'revoked {args.sensor_id}')
        elif args.command == 'upgrade':
            from brain import upgrades
            if args.action == 'stage':
                if not (args.file or args.version):
                    print('stage needs --file or --version', file=sys.stderr)
                    return 2
                t = upgrades.stage_file(args.file) if args.file else upgrades.stage_release(args.version)
                print(f"staged {t['version']} (sha256 {t['sha256'][:16]}…); sensors pick it up within 15 minutes")
            elif args.action == 'clear':
                upgrades.clear()
                print('no upgrade staged')
            else:
                print(json.dumps({'staged': upgrades.target(), 'sensors': [
                    {'id': s['id'], 'name': s['name'], 'version': (s['health'] or {}).get('version')}
                    for s in manage.store().list_sensors() if not s['revoked']]}, indent=2))
        elif args.command == 'command':
            env = manage.issue_command(args.sensor_id, args.action, args.ip, args.ttl, args.reason)
            print(f"queued command {env['payload']['seq']} for {args.sensor_id}")
    except KeyError as exc:
        print(f'no such sensor: {exc.args[0]}', file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
