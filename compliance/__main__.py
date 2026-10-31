"""python -m compliance list | report PACK [--pdf FILE]"""
import argparse
import json
import sys

from compliance import packs


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m compliance',
                                     description='Compliance evidence (documentation support, not certification).')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help='available packs')
    p = sub.add_parser('report', help='evidence report for one pack')
    p.add_argument('pack', choices=sorted(packs.PACKS))
    p.add_argument('--pdf', help='also write a PDF here')
    args = parser.parse_args(argv)
    if args.command == 'list':
        for name, p in packs.PACKS.items():
            print(f"{name:<10} {p['title']} ({len(p['controls'])} controls)")
        return 0
    report = packs.report(args.pack)
    if args.pdf:
        from compliance.pdf import render
        with open(args.pdf, 'wb') as f:
            f.write(render(report))
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
