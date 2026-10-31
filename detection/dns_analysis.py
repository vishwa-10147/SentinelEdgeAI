"""DNS tunnelling and DGA detection from query names (no payload inspection needed).

Tunnelling: long, high-entropy labels under one parent domain, many unique
subdomains per minute. DGA: the registrable label itself looks random
(entropy, consonant runs, few vowels) and many lookups fail with NXDOMAIN.
"""
import math
import time
from collections import Counter, deque

from common.bounded import BoundedDict
from detection.detectors import MAX_KEYS, MAX_SOURCES, Cooldown, Finding

VOWELS = set('aeiou')
COMMON_SUFFIXES = {'com', 'net', 'org', 'io', 'co', 'uk', 'de', 'in', 'edu', 'gov', 'local', 'lan', 'arpa'}


def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def split_name(qname):
    """('sub.labels', 'parent.tld', 'label') for a query name."""
    labels = [l for l in qname.lower().rstrip('.').split('.') if l]
    if len(labels) < 2:
        return '', qname.lower(), labels[0] if labels else ''
    cut = 3 if len(labels) >= 3 and labels[-2] in COMMON_SUFFIXES and len(labels[-1]) == 2 else 2
    parent = '.'.join(labels[-cut:])
    return '.'.join(labels[:-cut]), parent, labels[-cut]


def dga_score(label):
    """0-1: how random a registrable label looks."""
    if len(label) < 8:
        return 0.0
    letters = [c for c in label if c.isalpha()]
    if not letters:
        return 0.0
    vowel_ratio = sum(c in VOWELS for c in letters) / len(letters)
    digits = sum(c.isdigit() for c in label) / len(label)
    longest_consonants = max((len(run) for run in ''.join('.' if c in VOWELS or not c.isalpha() else c
                                                          for c in label).split('.')), default=0)
    score = 0.0
    score += min(1.0, max(0.0, (entropy(label) - 2.8) / 1.2)) * 0.45
    score += (0.3 if vowel_ratio < 0.25 else 0.15 if vowel_ratio < 0.32 else 0.0)
    score += min(0.15, digits)
    score += 0.1 if longest_consonants >= 5 else 0.0
    score += 0.1 if len(label) >= 14 else 0.0
    return min(1.0, score)


class DNSDetector:
    def __init__(self, window=60, tunnel_unique=30, tunnel_label=40, tunnel_entropy=3.5,
                 dga_names=10, dga_nx_ratio=0.5):
        self.window = window
        self.queries = BoundedDict(MAX_KEYS, deque)        # (src, parent) -> (ts, sub)
        self.lookups = BoundedDict(MAX_SOURCES, deque)     # src -> (ts, label, nxdomain, dga)
        self.tunnel_unique, self.tunnel_label, self.tunnel_entropy = tunnel_unique, tunnel_label, tunnel_entropy
        self.dga_names, self.dga_nx_ratio = dga_names, dga_nx_ratio
        self.cooldown = Cooldown(600)

    def observe(self, src, qname, nxdomain=False, ts=None):
        ts = ts or time.time()
        sub, parent, label = split_name(qname)
        out = []
        q = self.queries[(src, parent)]
        q.append((ts, sub))
        while q and q[0][0] < ts - self.window:
            q.popleft()
        subs = {s for _, s in q if s}
        long_labels = [s for s in subs if max((len(x) for x in s.split('.')), default=0) >= self.tunnel_label
                       or entropy(s.replace('.', '')) >= self.tunnel_entropy]
        if len(subs) >= self.tunnel_unique and len(long_labels) >= self.tunnel_unique // 2 \
                and self.cooldown.ready(('dns_tunnel', src, parent), ts):
            avg_len = sum(len(s) for s in subs) / len(subs)
            out.append(Finding('dns_tunnel', src, 85, 0.9, 'T1071.004',
                               f'{len(subs)} unique high-entropy subdomains of {parent} in {self.window}s '
                               f'(average {avg_len:.0f} characters)',
                               {'domain': parent, 'unique_subdomains': len(subs)}, ts=ts))
        lq = self.lookups[src]
        lq.append((ts, label, bool(nxdomain), dga_score(label)))
        while lq and lq[0][0] < ts - self.window * 5:
            lq.popleft()
        suspicious = [(lbl, nx) for _, lbl, nx, sc in lq if sc >= 0.6]
        if len({l for l, _ in suspicious}) >= self.dga_names:
            nx_ratio = sum(1 for _, _, nx, _ in lq if nx) / len(lq)
            if nx_ratio >= self.dga_nx_ratio and self.cooldown.ready(('dga', src), ts):
                out.append(Finding('dga', src, 80, 0.85, 'T1568.002',
                                   f'{len({l for l, _ in suspicious})} random-looking domains, '
                                   f'{nx_ratio * 100:.0f}% of lookups failed (NXDOMAIN)',
                                   {'examples': sorted({l for l, _ in suspicious})[:5],
                                    'nxdomain_ratio': round(nx_ratio, 2)}, ts=ts))
        return out
