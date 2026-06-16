from __future__ import annotations

import threading
import time
from collections import deque


class RealtimeBatcher:
    def __init__(self, sender=None, flush_interval=1.0, max_batch=50):
        self.sender = sender or (lambda event_type, payload: None)
        self.flush_interval = float(flush_interval)
        self.max_batch = int(max_batch)
        self._queue = deque()
        self._lock = threading.Lock()
        self._last_flush = 0.0

    def emit(self, event_type, payload):
        with self._lock:
            self._queue.append((event_type, payload))
            while len(self._queue) > self.max_batch:
                self._queue.popleft()
        self.flush_if_due()

    def flush_if_due(self):
        now = time.time()
        if now - self._last_flush < self.flush_interval:
            return 0
        return self.flush()

    def flush(self):
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
            self._last_flush = time.time()
        for event_type, payload in items:
            self.sender(event_type, payload)
        return len(items)


_batcher = RealtimeBatcher()


def configure_realtime(sender=None, flush_interval=1.0, max_batch=50):
    global _batcher
    _batcher = RealtimeBatcher(sender=sender, flush_interval=flush_interval, max_batch=max_batch)
    return _batcher


def emit_realtime(event_type, payload):
    _batcher.emit(event_type, payload)
