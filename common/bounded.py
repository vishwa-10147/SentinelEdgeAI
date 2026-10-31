"""Bounded per-key state, so a flood of spoofed addresses cannot exhaust memory.

BoundedDict behaves like a dict (or a defaultdict when given a factory) that
keeps at most `max_keys` keys: adding one more drops the oldest key. Detectors
keep per-source state in it; under a flood they forget the oldest sources
instead of growing without limit. `evicted` counts what was dropped.
"""
from collections import OrderedDict


class BoundedDict(OrderedDict):
    def __init__(self, max_keys, factory=None):
        super().__init__()
        self.max_keys = int(max_keys)
        self.factory = factory
        self.evicted = 0

    def __missing__(self, key):
        if self.factory is None:
            raise KeyError(key)
        value = self.factory()
        self[key] = value
        return value

    def __setitem__(self, key, value):
        new = key not in self
        super().__setitem__(key, value)
        if new:
            while len(self) > self.max_keys:
                self.popitem(last=False)
                self.evicted += 1

    def touch(self, key):
        """Mark `key` as recently used, so it is evicted last."""
        self.move_to_end(key)


class BoundedSet:
    """A set that keeps at most `max_items` members (the oldest are dropped first)."""

    def __init__(self, max_items):
        self._d = BoundedDict(max_items)

    def add(self, item):
        self._d[item] = True

    def __contains__(self, item):
        return item in self._d

    def __len__(self):
        return len(self._d)

    def discard(self, item):
        self._d.pop(item, None)

    @property
    def evicted(self):
        return self._d.evicted
