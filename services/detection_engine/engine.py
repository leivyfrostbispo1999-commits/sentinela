import fnmatch
import hashlib
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import yaml


SEVERITY_SCORE = {"INFO": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def stable_uuid(*parts):
    digest = hashlib.sha256("|".join(str(part or "") for part in parts).encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest[:32]))


class RuleSet:
    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.loaded_at = 0
        self.signature = None

    def maybe_reload(self):
        files = sorted(self.rules_dir.glob("*.yaml"))
        signature = tuple((str(path), path.stat().st_mtime_ns) for path in files)
        if signature == self.signature:
            return False
        rules = []
        for path in files:
            with path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or {}
            if isinstance(loaded, dict):
                loaded.setdefault("id", path.stem)
                loaded["_path"] = str(path)
                rules.append(loaded)
        self.rules = rules
        self.loaded_at = time.time()
        self.signature = signature
        return True


class DetectionEngine:
    def __init__(self, rules_dir, max_events=5000):
        self.ruleset = RuleSet(rules_dir)
        self.events_by_key = defaultdict(deque)
        self.max_events = max_events
        self.ruleset.maybe_reload()

    def _key(self, event, rule):
        field = rule.get("group_by") or "source_ip"
        return str(event.get(field) or event.get("source_ip") or event.get("host") or "unknown")

    def _remember(self, event):
        keys = {str(event.get("source_ip") or "unknown"), str(event.get("username") or "unknown"), str(event.get("host") or "unknown")}
        now = time.time()
        for key in keys:
            bucket = self.events_by_key[key]
            bucket.append((now, event))
            while len(bucket) > self.max_events:
                bucket.popleft()
            while bucket and now - bucket[0][0] > 3600:
                bucket.popleft()

    def match_condition(self, event, condition):
        if not condition:
            return True
        for field, expected in condition.items():
            actual = event.get(field)
            if field == "raw_log_contains":
                raw = str(event.get("raw_log") or "").lower()
                values = expected if isinstance(expected, list) else [expected]
                if not any(str(item).lower() in raw for item in values):
                    return False
                continue
            if field == "raw_log_regex":
                if not re.search(str(expected), str(event.get("raw_log") or ""), re.I):
                    return False
                continue
            values = expected if isinstance(expected, list) else [expected]
            if not any(fnmatch.fnmatch(str(actual or "").upper(), str(item).upper()) for item in values):
                return False
        return True

    def window_count(self, event, rule):
        window_seconds = int(rule.get("window_seconds") or 0)
        threshold = int(rule.get("threshold") or 1)
        if threshold <= 1:
            return 1
        key = self._key(event, rule)
        now = time.time()
        events = [item for ts, item in self.events_by_key.get(key, []) if now - ts <= window_seconds]
        condition = rule.get("condition") or {}
        return sum(1 for item in events if self.match_condition(item, condition))

    def evaluate(self, event):
        self.ruleset.maybe_reload()
        self._remember(event)
        alerts = []
        for rule in self.ruleset.rules:
            condition = rule.get("condition") or {}
            if not self.match_condition(event, condition):
                continue
            count = self.window_count(event, rule)
            threshold = int(rule.get("threshold") or 1)
            if count < threshold:
                continue
            severity = str(rule.get("severity") or event.get("severity") or "MEDIUM").upper()
            score = int(rule.get("score") or SEVERITY_SCORE.get(severity, 55))
            mitre = rule.get("mitre") or {}
            alert_id = stable_uuid(rule.get("id"), event.get("event_id"), self._key(event, rule), count)
            alerts.append(
                {
                    "event_id": alert_id,
                    "idempotency_key": f"{rule.get('id')}:{event.get('event_id')}:{self._key(event, rule)}",
                    "ip": event.get("source_ip") or "0.0.0.0",
                    "source_ip": event.get("source_ip"),
                    "target_ip": event.get("destination_ip"),
                    "target_host": event.get("host"),
                    "target_user": event.get("username"),
                    "service": event.get("service"),
                    "event_type": rule.get("event_type") or event.get("event_type"),
                    "severity": severity,
                    "status": rule.get("name") or rule.get("id"),
                    "risco": score,
                    "score_final": score,
                    "threat_score": score,
                    "event_count": count,
                    "ip_event_count": count,
                    "ts": event.get("timestamp") or now_iso(),
                    "mitre_id": mitre.get("technique"),
                    "mitre_name": mitre.get("technique_name"),
                    "mitre_tactic": mitre.get("tactic"),
                    "mitre_techniques": [mitre] if mitre else [],
                    "internal_rule_id": rule.get("id"),
                    "internal_rule_name": rule.get("name"),
                    "detection_source": "sentinela_detection_engine",
                    "human_summary": rule.get("description"),
                    "explanation": rule.get("description"),
                    "correlation_reasons": [f"Rule {rule.get('id')} matched {count}/{threshold} events"],
                    "risk_reasons": rule.get("tags") or [],
                    "raw_event": event,
                    "event_schema_version": event.get("event_schema_version") or "sentinela.event.v3",
                    "pipeline_priority": "high" if severity in {"HIGH", "CRITICAL"} else "medium",
                    "tenant_id": event.get("tenant_id") or "default",
                    "correlation_id": event.get("correlation_id") or event.get("event_id"),
                    "recommended_action": rule.get("recommended_action") or "Investigar evento e preservar evidencias.",
                    "execution_mode": "simulation",
                    "execution_status": "not_executed",
                }
            )
        return alerts
