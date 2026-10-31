"""python -m fleet init | code | sites | revoke | template | templates | group | groups | rollout | federated | enroll | report | status"""
import argparse
import json
import sys

from fleet import agent, keys, manage
from fleet.store import FleetStore



def _show(obj):
    print(json.dumps(obj, indent=2, default=str))


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m fleet', description='SentinelEdgeAI fleet manager.')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init', help='make this device a fleet server (keys + start marker)')
    p = sub.add_parser('code', help='one-time enrolment code for a new site')
    p.add_argument('--group', default='default')
    sub.add_parser('sites', help='enrolled sites and their latest reports')
    p = sub.add_parser('revoke', help='revoke a site')
    p.add_argument('site_id')
    p = sub.add_parser('template', help='store a configuration template (response policy YAML)')
    p.add_argument('name')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--file')
    src.add_argument('--preset', choices=['home', 'office', 'ot', 'enterprise'])
    sub.add_parser('templates', help='stored templates')
    p = sub.add_parser('group', help='create or update a group')
    p.add_argument('name')
    p.add_argument('--template')
    p.add_argument('--version', help='target version; a new one starts a staged rollout')
    p.add_argument('--stages', help='JSON list of {"percent", "hours"}; default 10%% now, 50%% after 24 h, 100%% after 48 h')
    sub.add_parser('groups', help='groups and their rollouts')
    p = sub.add_parser('rollout', help='pause or resume a group\'s rollout')
    p.add_argument('action', choices=['pause', 'resume'])
    p.add_argument('group')
    p = sub.add_parser('federated', help='federated learning rounds (sites share model updates, never data)')
    p.add_argument('action', choices=['status', 'start', 'close'])
    p.add_argument('--min-sites', type=int, default=2, help='aggregate once this many sites have answered')
    p.add_argument('--round', type=int)
    p = sub.add_parser('enroll', help='enrol this site with a fleet server')
    p.add_argument('url')
    p.add_argument('code')
    p.add_argument('fingerprint')
    p.add_argument('--name')
    sub.add_parser('report', help='send one report now and apply the desired state')
    sub.add_parser('status', help='this site\'s fleet status')
    args = parser.parse_args(argv)

    try:
        if args.command == 'enroll':
            print(agent.enroll(args.url, args.code, args.fingerprint, args.name))
            return 0
        if args.command == 'report':
            _show(agent.report_once())
            return 0
        if args.command == 'status':
            _show(agent.status())
            return 0
        if args.command == 'init':
            keys.init()
            print(f'fleet server ready; CA fingerprint {keys.ca_fingerprint()}')
            return 0
        st = FleetStore()
        if args.command == 'code':
            c = manage.enrolment_code(args.group, 'cli', st)
            print(f"{c['code']}\non the site: python -m fleet enroll https://<this-device>:9444 {c['code']} {c['ca_fingerprint']}")
        elif args.command == 'sites':
            _show(st.list_sites())
        elif args.command == 'revoke':
            print('revoked' if st.revoke_site(args.site_id) else 'no such site')
        elif args.command == 'template':
            text = None
            if args.file:
                with open(args.file, 'r', encoding='utf-8') as f:
                    text = f.read()
            print(manage.put_template(args.name, text, args.preset, 'cli', st))
        elif args.command == 'templates':
            _show(st.list_templates())
        elif args.command == 'group':
            _show(manage.put_group(args.name, args.template, args.version,
                                   json.loads(args.stages) if args.stages else None, 'cli', st))
        elif args.command == 'groups':
            _show(manage.overview(st)['groups'])
        elif args.command == 'federated':
            if args.action == 'start':
                _show(manage.start_round(args.min_sites, by='cli', st=st))
            elif args.action == 'close':
                _show(manage.close_round(args.round, by='cli', st=st))
            else:
                _show(st.rounds())
        elif args.command == 'rollout':
            _show(manage.set_rollout(args.group, args.action, 'cli', st))
        return 0
    except (ValueError, agent.AgentError, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
