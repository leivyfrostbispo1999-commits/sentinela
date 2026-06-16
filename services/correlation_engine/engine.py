from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


ENTITY_FIELDS = ("source_ip", "destination_ip", "username", "host", "target_host", "process", "container", "session_id")


def parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


class CorrelationEngine:
    def __init__(self, window_seconds=900):
        self.window_seconds = window_seconds

    def entities_for(self, event):
        entities = {}
        for field in ENTITY_FIELDS:
            value = event.get(field)
            if value:
                entities[field] = str(value)
        return entities

    def correlate(self, events):
        ordered = sorted((dict(event) for event in events), key=lambda item: parse_time(item.get("timestamp") or item.get("ts")))
        graph = defaultdict(set)
        clusters = []
        current = []
        last_ts = None

        for event in ordered:
            ts = parse_time(event.get("timestamp") or event.get("ts"))
            entities = self.entities_for(event)
            keys = [f"{field}:{value}" for field, value in entities.items()]
            for left in keys:
                for right in keys:
                    if left != right:
                        graph[left].add(right)
            if not current or (last_ts and (ts - last_ts).total_seconds() <= self.window_seconds):
                current.append(event)
            else:
                clusters.append(current)
                current = [event]
            last_ts = ts
        if current:
            clusters.append(current)

        return {
            "entity_graph": {key: sorted(values) for key, values in graph.items()},
            "attack_chains": [self.describe_chain(cluster) for cluster in clusters],
            "lateral_movement_indicators": self.lateral_movement(ordered),
            "repeated_iocs": self.repeated_iocs(ordered),
            "user_behavior": self.user_behavior(ordered),
        }

    def describe_chain(self, cluster):
        scores = [int(item.get("threat_score") or item.get("score_final") or item.get("risco") or 0) for item in cluster]
        return {
            "event_count": len(cluster),
            "first_seen": (cluster[0].get("timestamp") or cluster[0].get("ts")) if cluster else None,
            "last_seen": (cluster[-1].get("timestamp") or cluster[-1].get("ts")) if cluster else None,
            "source_ips": sorted({item.get("source_ip") or item.get("ip") for item in cluster if item.get("source_ip") or item.get("ip")}),
            "hosts": sorted(
                {item.get("host") or item.get("target_host") for item in cluster if item.get("host") or item.get("target_host")}
            ),
            "users": sorted(
                {item.get("username") or item.get("target_user") for item in cluster if item.get("username") or item.get("target_user")}
            ),
            "mitre_sequence": list(
                dict.fromkeys(
                    item.get("mitre_id") or item.get("technique") for item in cluster if item.get("mitre_id") or item.get("technique")
                )
            ),
            "risk_score": max(scores, default=0),
        }

    def lateral_movement(self, events):
        by_ip = defaultdict(set)
        for event in events:
            source = event.get("source_ip") or event.get("ip")
            host = event.get("host") or event.get("target_host")
            if source and host:
                by_ip[source].add(host)
        return [
            {"source_ip": source, "host_count": len(hosts), "hosts": sorted(hosts)} for source, hosts in by_ip.items() if len(hosts) > 1
        ]

    def repeated_iocs(self, events):
        counts = defaultdict(int)
        for event in events:
            for key in ("source_ip", "mitre_id", "technique", "username"):
                value = event.get(key)
                if value:
                    counts[f"{key}:{value}"] += 1
        return [{"ioc": key, "count": count} for key, count in counts.items() if count >= 3]

    def user_behavior(self, events):
        users = defaultdict(lambda: {"event_count": 0, "hosts": set(), "max_score": 0})
        for event in events:
            user = event.get("username") or event.get("target_user")
            if not user:
                continue
            item = users[user]
            item["event_count"] += 1
            if event.get("host") or event.get("target_host"):
                item["hosts"].add(event.get("host") or event.get("target_host"))
            item["max_score"] = max(
                item["max_score"], int(event.get("threat_score") or event.get("score_final") or event.get("risco") or 0)
            )
        return {
            user: {"event_count": data["event_count"], "hosts": sorted(data["hosts"]), "max_score": data["max_score"]}
            for user, data in users.items()
        }
