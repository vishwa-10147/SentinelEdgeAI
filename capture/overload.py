"""Capture overload monitor: notices when the appliance cannot keep up (a flood) and says so once.

Every OVERLOAD_EVERY seconds it compares the flow table's eviction counter and the scoring
queue's shed counter with the previous check. Any increase means flows are being forgotten
or not scored: capture is "overloaded". It then raises one alert per OVERLOAD_ALERT_EVERY
seconds, exports the numbers as Prometheus metrics and reports them in the health file.
"""
import logging
import time

logger = logging.getLogger('sentinel.capture')
OVERLOAD_EVERY = 10.0
OVERLOAD_ALERT_EVERY = 600.0


class OverloadMonitor:
    def __init__(self, flow_table, alert, every=OVERLOAD_EVERY, alert_every=OVERLOAD_ALERT_EVERY):
        self.flow_table = flow_table
        self.alert = alert                        # callable(dict): the engine's alert logger
        self.every, self.alert_every = every, alert_every
        self.ingest_shed = 0                      # flows dropped because the scoring queue was full
        self.overloaded = False
        self._checked = self._alerted = None
        self._last = {'evicted': 0, 'shed': 0, 'ingest_shed': 0}

    def stats(self):
        return {**self.flow_table.stats(), 'ingest_shed_total': self.ingest_shed, 'overloaded': self.overloaded}

    def check(self, now_mono):
        if self._checked is not None and now_mono - self._checked < self.every:
            return
        self._checked = now_mono
        st = self.flow_table.stats()
        evicted = st['evicted_total'] - self._last['evicted']
        ingest = self.ingest_shed - self._last['ingest_shed']
        self._last = {'evicted': st['evicted_total'], 'shed': st['shed_total'], 'ingest_shed': self.ingest_shed}
        self.overloaded = bool(evicted or ingest)
        self._metrics(st)
        if not self.overloaded:
            return
        logger.warning('capture overloaded: %d flows evicted, %d dropped from scoring in %.0f s; flow table %d/%d',
                       evicted, ingest, self.every, st['active'], st['max'])
        if self._alerted is not None and now_mono - self._alerted < self.alert_every:
            return
        self._alerted = now_mono
        try:
            self.alert({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'initiator_ip': None, 'responder_ip': None,
                'protocol': 'CAPTURE', 'final_risk_score': 70, 'severity': 'HIGH', 'attack_type': 'capture_overload',
                'confidence': 0.9, 'mitre_technique_id': 'T1498',
                'explanation': [f"More new flows than the appliance can track ({st['active']} active, limit {st['max']}): "
                                f'{evicted} flows evicted and {ingest} dropped from scoring in the last {self.every:.0f} s. '
                                'Possible flood or spoofed-address scan; detection is degraded until it stops.'],
                'details': self.stats(),
            })
        except Exception:
            logger.debug('overload alert failed', exc_info=True)

    def _metrics(self, st):
        try:
            from utils import metrics
            if metrics.CAPTURE is None:
                return
            for k in ('active', 'max', 'evicted_total', 'shed_total'):
                metrics.CAPTURE.labels(k).set(st[k])
            metrics.CAPTURE.labels('ingest_shed_total').set(self.ingest_shed)
            metrics.CAPTURE.labels('overloaded').set(1 if self.overloaded else 0)
        except Exception:
            pass
