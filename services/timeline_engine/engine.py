from __future__ import annotations

from datetime import datetime, timezone


SEVERITY_WEIGHT = {"INFO": 5, "LOW": 15, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 95}


def parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)


def alert_time(alert):
    return parse_time(alert.get("timestamp") or alert.get("ts") or alert.get("first_seen") or alert.get("last_seen"))


def risk(alert):
    return int(
        alert.get("threat_score")
        or alert.get("score_final")
        or alert.get("risco")
        or SEVERITY_WEIGHT.get(str(alert.get("severity") or "LOW").upper(), 10)
    )


def timeline_message(alert):
    return (
        alert.get("human_summary")
        or alert.get("explanation")
        or alert.get("status")
        or f"{alert.get('event_type') or 'event'} observado em {alert.get('target_host') or alert.get('host') or 'host desconhecido'}"
    )


def chain_key(alert):
    return "|".join(
        str(alert.get(key) or "")
        for key in ("source_ip", "target_host", "target_user", "service", "session_id", "container_name", "correlation_id")
    )


def build_incident_timeline(incident_id, alerts, correlation_window_seconds=300):
    ordered = sorted((dict(alert) for alert in alerts), key=alert_time)
    timeline = []
    accumulated = 0
    previous = None
    mitre_sequence = []
    correlation_ids = set()

    for index, alert in enumerate(ordered):
        current_time = alert_time(alert)
        score = risk(alert)
        accumulated = min(100, accumulated + max(1, score // 10))
        mitre = alert.get("mitre_id") or alert.get("technique") or ""
        if mitre and mitre not in mitre_sequence:
            mitre_sequence.append(mitre)
        correlation_id = alert.get("correlation_id") or alert.get("idempotency_key") or chain_key(alert)
        if correlation_id:
            correlation_ids.add(str(correlation_id))
        gap = None
        if previous:
            gap = max(0, int((current_time - previous).total_seconds()))
        previous = current_time
        related = gap is None or gap <= correlation_window_seconds

        timeline.append(
            {
                "timestamp": current_time.isoformat(),
                "event_type": alert.get("event_type") or "UNKNOWN",
                "severity": str(alert.get("severity") or "LOW").upper(),
                "message": timeline_message(alert),
                "mitre_technique": mitre,
                "mitre_tactic": alert.get("mitre_tactic") or "",
                "host": alert.get("target_host") or alert.get("host") or "",
                "source_ip": alert.get("source_ip") or alert.get("ip") or "",
                "username": alert.get("target_user") or alert.get("username") or "",
                "container": alert.get("target_container") or alert.get("container_name") or "",
                "session_id": alert.get("session_id") or "",
                "score": score,
                "accumulated_score": accumulated,
                "sequence_index": index + 1,
                "correlation_id": correlation_id,
                "related_to_previous": related,
                "gap_seconds": gap,
                "badges": [item for item in [str(alert.get("severity") or "").upper(), mitre, alert.get("service")] if item],
            }
        )

    return {
        "incident_id": incident_id,
        "risk_score": max([risk(alert) for alert in ordered], default=0),
        "accumulated_score": accumulated,
        "event_count": len(timeline),
        "mitre_sequence": mitre_sequence,
        "correlation_ids": sorted(correlation_ids),
        "timeline": timeline,
    }
