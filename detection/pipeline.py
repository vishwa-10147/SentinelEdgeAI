"""Phase 4 detection pipeline: detectors + DNS + TLS + fusion, used by the engine and the evaluator."""
import threading
import time

from detection.detectors import default_flow_detectors
from detection.dns_analysis import DNSDetector
from detection.fusion import Fusion
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
    def __init__(self, flow_detectors=None, dns=None, tls=None, clock=time.time, calibrate=None, models=True):
        self.flow_detectors = flow_detectors if flow_detectors is not None else default_flow_detectors()
        self.dns = dns or DNSDetector()
        self.tls = tls or TLSDetector(clock=clock)
        self.fusion = Fusion(clock=clock, calibrate=calibrate)
        self.clock = clock
        self.autoencoder = None
        if models:
            from detection.registry import ModelHandle
            self.autoencoder = ModelHandle('autoencoder')
        self.shadow_scores = 0
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
        return fused

    def observe_dns(self, src, qname, nxdomain=False, ts=None):
        with self._lock:
            findings = self.dns.observe(src, qname, nxdomain, ts or self.clock())
            self.fusion.add_findings(findings)
        return findings

    def observe_tls(self, src, dst, payload, ts=None):
        hello = parse_client_hello(payload)
        if not hello:
            return None, []
        with self._lock:
            findings = self.tls.observe(src, dst, hello, ts or self.clock())
            self.fusion.add_findings(findings)
        return hello, findings


_pipeline = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        _pipeline = DetectionPipeline(calibrate=_FeedbackCalibration())
    return _pipeline
