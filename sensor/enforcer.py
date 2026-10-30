"""Executes brain commands on the sensor, after verifying them.

A command is applied only if all of these hold:
  * its Ed25519 signature verifies with the brain key pinned at enrolment;
  * it is addressed to this sensor;
  * its sequence number is higher than any command applied before
    (persisted, so a replay after a restart is also refused);
  * it has not expired;
  * the local whitelist allows it (core.firewall refuses whitelisted IPs).
"""
import json
import os
import threading
import time

import core.audit as audit
import core.firewall as firewall
from common import signing
from common.protocol import COMMAND_ACTIONS


class CommandRejected(ValueError):
    pass


class Enforcer:
    def __init__(self, sensor_id, brain_public_key, state_file, firewall_module=None, clock=time.time):
        self.sensor_id = sensor_id
        self.public_key = brain_public_key
        self.state_file = state_file
        self.firewall = firewall_module or firewall
        self.clock = clock
        self._lock = threading.Lock()

    def last_seq(self):
        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                return int(json.load(f).get('last_seq', 0))
        except (OSError, ValueError):
            return 0

    def _store_seq(self, seq):
        tmp = self.state_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump({'last_seq': seq}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_file)

    def check(self, envelope):
        """Return the verified command payload or raise CommandRejected."""
        try:
            cmd = signing.verify(self.public_key, envelope)
        except signing.SignatureError as exc:
            raise CommandRejected(f'forged: {exc}')
        if cmd.get('sensor_id') != self.sensor_id:
            raise CommandRejected('addressed to another sensor')
        try:
            seq = int(cmd.get('seq'))
        except (TypeError, ValueError):
            raise CommandRejected('missing sequence number')
        if seq <= self.last_seq():
            raise CommandRejected(f'replayed: sequence {seq} already applied')
        if int(cmd.get('expires', 0)) < self.clock():
            raise CommandRejected('expired')
        if cmd.get('action') not in COMMAND_ACTIONS:
            raise CommandRejected(f"unknown action {cmd.get('action')!r}")
        return cmd

    def apply(self, envelope):
        """Verify and execute one command. Returns {'seq', 'status', 'detail'}."""
        with self._lock:
            payload = envelope.get('payload') if isinstance(envelope, dict) else None
            seq = payload.get('seq') if isinstance(payload, dict) else None
            try:
                cmd = self.check(envelope)
            except CommandRejected as exc:
                audit.record('sensor_command', actor='brain', actor_kind='brain', target=str(seq),
                             outcome='rejected', details={'reason': str(exc)})
                return {'seq': seq, 'status': 'rejected', 'detail': str(exc)}
            # consume the sequence number before acting, so a crash mid-way
            # can never lead to the same command running twice
            self._store_seq(cmd['seq'])
            try:
                result = self._execute(cmd)
                status, detail = 'applied', result
            except ValueError as exc:
                # e.g. the local whitelist refused the block
                status, detail = 'refused', str(exc)
            audit.record('sensor_command', actor='brain', actor_kind='brain', target=cmd.get('ip'),
                         outcome='success' if status == 'applied' else status,
                         details={'seq': cmd['seq'], 'action': cmd['action'], 'reason': cmd.get('reason'),
                                  'detail': detail if status != 'applied' else None})
            return {'seq': cmd['seq'], 'status': status, 'detail': detail}

    def _execute(self, cmd):
        action = cmd['action']
        reason = f"brain:{cmd.get('reason') or 'command'}"
        if action == 'block':
            rule = self.firewall.add_block(cmd['ip'], ttl=cmd.get('ttl'), reason=reason)
            return {'ip': rule.get('ip'), 'dry_run': rule.get('dry_run')}
        if action == 'unblock':
            return self.firewall.remove_block(cmd['ip'])
        return self.firewall.rollback_blocks(reason=reason)
