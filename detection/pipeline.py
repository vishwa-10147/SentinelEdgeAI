"""Detection pipeline: detectors + DNS + TLS + OT protocols + fusion, used by the engine and the evaluator."""
import threading
import time

from detection.detectors import default_flow_detectors
from detection.dns_analysis import DNSDetector
from detection.fusion import Fusion
from detection.ot import OTDetector, OTStore, parse_ot
from detection.tls import TLSDetector, parse_client_hello


class _FeedbackCalibration:
    """Detector probabilities recalibrated from analyst labels (cached for a minute)."""

    def __init__(self):
        self._counts, self._at = {}, 0.0

    def __call__(self, kind, prior):
        now = time.time()
        if now - self._at > 60:
            try:
                from detection.feedback import get_store
                self._counts = get_store().counts()
            except Exception:
                self._counts = {}
            self._at = now
        c = self._counts.get(kind)
        if not c:
            return prior
        from detection.feedback import PRIOR_WEIGHT
        return (c['tp'] + prior * PRIOR_WEIGHT) / (c['tp'] + c['fp'] + PRIOR_WEIGHT)


class DetectionPipeline:
    def __init__(self, flow_detectors=None, dns=None, tls=None, ot=None, peers=None, clock=time.time, calibrate=None,
                 models=True):
        self.flow_detectors = flow_detectors if flow_detectors is not None else default_flow_detectors()
        self.dns = dns or DNSDetector()
        self.tls = tls or TLSDetector(clock=clock)
        self.ot = ot or OTDetector(clock=clock)
        self.peers = peers                    # detection.peers.PeerStore: learned peer profiles
        self.fusion = Fusion(clock=clock, calibrate=calibrate)
        self.clock = clock
        self.autoencoder = None
        if models:
            from detection.registry import ModelHandle
            self.autoencoder = ModelHandle('autoencoder')
        self.shadow_scores = 0
        self.intel_enabled = models
        self._lock = threading.Lock()

    def _model_findings(self, record):
        if self.autoencoder is None or not record.get('features'):
            return []
        from detection.autoencoder import finding_for
        out = []
        try:
            shadow = self.autoencoder.shadow()
            if shadow:
                finding_for(record, shadow[2], 'shadow')   # scored and counted, never acted on
                self.shadow_scores += 1
            chosen = self.autoencoder.for_source(record['src'])
            if chosen:
                f = finding_for(record, chosen[2], chosen[0])
                if f:
                    out.append(f)
        except Exception:
            pass
        return out

    def observe_flow(self, record, engine_result=None):
        """Score one finished flow. Returns the fused result (see detection.fusion)."""
        engine_result = engine_result or {}
        record.setdefault('ts', self.clock())
        with self._lock:
            findings = []
            for det in self.flow_detectors:
                try:
                    findings.extend(det.observe(record))
                except Exception:
                    continue
            findings.extend(self._model_findings(record))
            self.fusion.add_findings(findings)
            fused = self.fusion.fuse(record['src'], engine_result.get('final_risk', 0) or 0,
                                     engine_result.get('confidence', 0) or 0, record.get('proto'),
                                     record.get('features'), now=record['ts'])
        fused['new_findings'] = [f.as_dict() for f in findings]
        if self.peers is not None:
            try:
                self.peers.observe(record)
            except Exception:
                pass
        return fused

    def _intel(self):
        try:
            from intel.store import get_store
            return get_store()
        except Exception:
            return None

    def observe_dns(self, src, qname, nxdomain=False, ts=None):
        from detection.detectors import Finding
        ts = ts or self.clock()
        with self._lock:
            findings = self.dns.observe(src, qname, nxdomain, ts)
            store = self._intel() if self.intel_enabled else None
            hit = store.match_domain(qname) if store else None
            if hit and self.dns.cooldown.ready(('intel_domain', src, qname), ts):
                findings.append(Finding('threat_intel', src, 85, 0.9, 'T1071.004',
                                        f'lookup of {qname.rstrip(".")}, listed by {hit[0]}' + (f' ({hit[1]})' if hit[1] else ''),
                                        {'indicator': qname.rstrip('.'), 'source': hit[0], 'label': hit[1]}, ts=ts))
            self.fusion.add_findings(findings)
        return findings

    def observe_tls(self, src, dst, payload, ts=None):
        hello = parse_client_hello(payload)
        if not hello:
            return None, []
        from detection.detectors import Finding
        ts = ts or self.clock()
        with self._lock:
            findings = self.tls.observe(src, dst, hello, ts)
            store = self._intel() if self.intel_enabled else None
            for fp in (hello['ja3'], hello['ja4']):
                hit = store.match_fingerprint(fp) if store else None
                if hit and self.tls.cooldown.ready(('intel_fp', src, fp), ts):
                    findings.append(Finding('tls_known_bad', src, 90, 0.9, 'T1071.001',
                                            f'TLS fingerprint {fp} listed by {hit[0]}' + (f' ({hit[1]})' if hit[1] else ''),
                                            {'fingerprint': fp, 'source': hit[0], 'target': dst}, ts=ts))
            self.fusion.add_findings(findings)
        return hello, findings

    def observe_ot(self, src, dst, proto, dport, payload, ts=None):
        """Feed a payload sent to an industrial protocol port. Returns (protocol, messages, findings)."""
        protocol, messages = parse_ot(proto, dport, payload)
        if not protocol:
            return None, [], []
        ts = ts or self.clock()
        with self._lock:
            findings = self.ot.observe(src, dst, protocol, messages, ts)
            self.fusion.add_findings(findings)
        return protocol, messages, findings


_pipeline = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        from detection.peers import PeerStore
        _pipeline = DetectionPipeline(calibrate=_FeedbackCalibration(), ot=OTDetector(store=OTStore()), peers=PeerStore())
    return _pipeline
