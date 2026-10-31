"""python -m brain init | code | sensors | revoke | command"""
import argparse
import json
import sys

from brain import keys, manage
from ops.backup import BackupError


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
    p = sub.add_parser('ha', help='active/standby brains sharing keys and a PostgreSQL database')
    p.add_argument('action', choices=['status', 'export', 'import'])
    p.add_argument('file', nargs='?', help='pairing bundle (export: where to write; import: what to read)')
    p.add_argument('--force', action='store_true', help='import even though this brain has a different CA')
    p = sub.add_parser('segment', help='put a sensor in a segment (sensors of one segment back each other up)')
    p.add_argument('sensor_id')
    p.add_argument('segment', nargs='?', help='leave out to remove the sensor from its segment')
    args = parser.parse_args(argv)
    if args.command == 'ha' and args.action == 'import':
        import getpass
        from brain import ha
        if not args.file:
            print('import needs the bundle file', file=sys.stderr)
            return 2
        try:
            out = ha.import_bundle(args.file, getpass.getpass('pairing passphrase: '), force=args.force)
        except (ValueError, OSError, BackupError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"paired: shared CA {out['ca_fingerprint']}; point SENTINEL_BRAIN_DATABASE_URL at the shared PostgreSQL")
        return 0

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
        elif args.command == 'ha':
            from brain import ha
            if args.action == 'export':
                import getpass
                if not args.file:
                    print('export needs a file to write', file=sys.stderr)
                    return 2
                phrase = getpass.getpass('pairing passphrase (12+ characters): ')
                if phrase != getpass.getpass('again: '):
                    print('passphrases differ', file=sys.stderr)
                    return 1
                print(json.dumps(ha.export_bundle(args.file, phrase), indent=2))
            else:
                print(json.dumps(ha.status(manage.store()), indent=2))
        elif args.command == 'segment':
            manage.store().set_segment(args.sensor_id, args.segment)
            print(f"{args.sensor_id}: segment {args.segment or '(none)'}")
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
    except (ValueError, OSError, BackupError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
