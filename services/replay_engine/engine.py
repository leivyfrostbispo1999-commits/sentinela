from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone


def parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def retention_plan(retention_days=30, archive_after_days=7, now=None):
    now = now or datetime.now(timezone.utc)
    return {
        "delete_before": (now - timedelta(days=retention_days)).isoformat(),
        "archive_before": (now - timedelta(days=archive_after_days)).isoformat(),
        "compact_before": (now - timedelta(days=max(1, archive_after_days // 2))).isoformat(),
        "retention_days": retention_days,
        "archive_after_days": archive_after_days,
    }


class ReplayEngine:
    def __init__(self):
        self.jobs = {}

    def start(self, events, filters=None):
        filters = filters or {}
        selected = self.filter_events(events, filters)
        replay_id = "RPL-" + uuid.uuid4().hex[:12].upper()
        self.jobs[replay_id] = {
            "replay_id": replay_id,
            "status": "completed",
            "queued": len(selected),
            "processed": len(selected),
            "filters": filters,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        return self.jobs[replay_id]

    def filter_events(self, events, filters):
        result = []
        start = parse_time(filters.get("start")) if filters.get("start") else None
        end = parse_time(filters.get("end")) if filters.get("end") else None
        for event in events:
            ts = parse_time(event.get("timestamp") or event.get("ts"))
            if start and ts < start:
                continue
            if end and ts > end:
                continue
            for key in ("incident_id", "host", "source_ip", "username"):
                if filters.get(key) and str(event.get(key) or event.get("target_host") or "") != str(filters[key]):
                    break
            else:
                result.append({**event, "is_replay_event": True})
        return result

    def status(self, replay_id=None):
        if replay_id:
            return self.jobs.get(replay_id, {"replay_id": replay_id, "status": "not_found"})
        return {"jobs": list(self.jobs.values()), "queue_size": sum(1 for item in self.jobs.values() if item["status"] == "queued")}
