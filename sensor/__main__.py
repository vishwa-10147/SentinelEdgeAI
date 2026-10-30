"""python -m sensor enroll | run | status"""
import argparse
import json
import logging
import sys

from sensor import uplink
from sensor.buffer import DiskBuffer


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m sensor', description='SentinelEdgeAI sensor link to the brain.')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('enroll', help='enrol this device with a brain')
    p.add_argument('--brain', required=True, help='e.g. https://brain.local:9443')
    p.add_argument('--code', required=True, help='one-time enrolment code from the brain')
    p.add_argument('--ca-fingerprint', required=True, help="the brain CA's SHA-256 fingerprint shown with the code")
    p.add_argument('--name', help='name shown on the brain (default: hostname)')
    sub.add_parser('run', help='send buffered flows to the brain and execute its signed commands')
    sub.add_parser('status', help='enrolment and buffer state')
    args = parser.parse_args(argv)

    if args.command == 'enroll':
        try:
            sensor_id = uplink.enroll(args.brain, args.code, args.ca_fingerprint, args.name)
        except uplink.EnrolmentError as exc:
            print(f'enrolment failed: {exc}', file=sys.stderr)
            return 1
        print(f'enrolled as {sensor_id}; start the link with: python -m sensor run')
        return 0
    if args.command == 'status':
        identity = uplink.load_identity()
        buf = DiskBuffer()
        print(json.dumps({'enrolled': identity, 'buffered': len(buf), 'dropped': buf.dropped()}, indent=2))
        return 0
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    try:
        link = uplink.Uplink()
    except uplink.EnrolmentError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    link.run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
