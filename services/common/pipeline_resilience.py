import hashlib
import os
import time


EVENT_SCHEMA_VERSION = os.getenv("EVENT_SCHEMA_VERSION", "sentinela.event.v2")

_PRIORITY_WEIGHT = {
    "high": 0.75,
    "medium": 1.0,
    "low": 1.25,
}


def normalize_priority(value):
    priority = str(value or "medium").strip().lower()
    return priority if priority in _PRIORITY_WEIGHT else "medium"


def get_priority_topic(base_topic, priority):
    priority = normalize_priority(priority)
    if priority == "high":
        return f"{base_topic}_high"
    if priority == "low":
        return f"{base_topic}_low"
    return base_topic  # medium


def get_all_priority_topics(base_topic):
    return [base_topic, f"{base_topic}_high", f"{base_topic}_low"]


def event_priority(event):
    if not isinstance(event, dict):
        return "medium"

    severity = str(event.get("severity") or "").strip().upper()
    status = str(event.get("status") or "").strip().upper()
    event_type = str(event.get("event_type") or event.get("type") or "").strip().upper()

    if severity == "CRITICAL" or status in {"IOC DETECTADO", "CAMPANHA HOSTIL", "ATAQUE MULTIETAPA"}:
        return "high"
    if severity == "HIGH" or event.get("distributed_attack") or event.get("should_blacklist"):
        return "high"
    if severity == "MEDIUM" or event_type in {"BRUTE_FORCE", "FAILED_LOGIN", "PORT_SCAN", "LOGIN_FAILED", "AUTH_FAILED"}:
        return "medium"
    return "low"


def retry_backoff_seconds(attempt, base_ms=500, max_seconds=15, priority="medium", jitter_ratio=0.15, seed=None):
    attempt = max(0, int(attempt or 0))
    base_delay = (float(base_ms) / 1000.0) * (2 ** min(attempt, 6))
    delay = min(float(max_seconds), base_delay)
    delay *= _PRIORITY_WEIGHT.get(normalize_priority(priority), 1.0)
    if jitter_ratio:
        source = seed if seed is not None else f"{attempt}:{priority}:{base_ms}:{max_seconds}"
        digest = hashlib.sha256(str(source).encode("utf-8")).digest()
        jitter = (int.from_bytes(digest[:8], "big") / float(2**64)) * 2 - 1
        delay += delay * float(jitter_ratio) * jitter
    return round(max(0.0, min(float(max_seconds), delay)), 3)


class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_seconds=30):
        self.failure_threshold = max(1, int(failure_threshold or 1))
        self.recovery_seconds = max(1, int(recovery_seconds or 1))
        self._failures = 0
        self._opened_at = None
        self._state = "closed"

    def allow(self, now=None):
        if self._state != "open":
            return True
        now = float(now if now is not None else time.time())
        if self._opened_at is None:
            return True
        if now - self._opened_at >= self.recovery_seconds:
            self._state = "half_open"
            self._failures = 0
            self._opened_at = None
            return True
        return False

    def record_success(self):
        self._state = "closed"
        self._failures = 0
        self._opened_at = None

    def record_failure(self, now=None):
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._state = "open"
            self._opened_at = float(now if now is not None else time.time())
        return self._state

    def remaining_seconds(self, now=None):
        if self._state != "open" or self._opened_at is None:
            return 0.0
        now = float(now if now is not None else time.time())
        return max(0.0, float(self.recovery_seconds) - (now - self._opened_at))

    def snapshot(self, now=None):
        return {
            "state": self._state,
            "failures": self._failures,
            "failure_threshold": self.failure_threshold,
            "recovery_seconds": self.recovery_seconds,
            "remaining_seconds": round(self.remaining_seconds(now=now), 3),
        }
