import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DLQ_TOPIC = os.getenv("DLQ_TOPIC", "dead_letter_events")
DEFAULT_TARGET_TOPIC = os.getenv("RAW_LOGS_TOPIC", "raw_logs")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def iter_jsonl(path):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def extract_original_event(item):
    if isinstance(item, dict) and "original_event" in item:
        return item.get("original_event") or {}
    return item


def load_events(args):
    if args.source == "file":
        if not args.file:
            raise SystemExit("--file e obrigatorio com --source file")
        yield from iter_jsonl(args.file)
        return
    if args.source != "dlq":
        raise SystemExit(f"source invalida: {args.source}")
    try:
        from kafka import KafkaConsumer
    except ImportError as exc:
        raise SystemExit("kafka-python nao instalado; use --source file para dry-run offline") from exc
    consumer = KafkaConsumer(
        args.dlq_topic,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=args.group_id,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=args.consumer_timeout_ms,
        value_deserializer=lambda message: json.loads(message.decode("utf-8")),
    )
    for message in consumer:
        yield message.value


def publish_events(events, target_topic):
    from kafka import KafkaProducer

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
    )
    count = 0
    for event in events:
        producer.send(target_topic, event)
        count += 1
    producer.flush(timeout=10)
    return count


def select_events(args):
    selected = []
    for item in load_events(args):
        event = extract_original_event(item)
        if args.tenant and (event.get("tenant_id") or item.get("tenant_id")) != args.tenant:
            continue
        event["tenant_id"] = event.get("tenant_id") or item.get("tenant_id") or os.getenv("DEFAULT_TENANT_ID", "default")
        event["correlation_id"] = event.get("correlation_id") or item.get("correlation_id") or event.get("event_id")
        selected.append(event)
        if args.limit and len(selected) >= args.limit:
            break
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay seguro de eventos/DLQ do SENTINELA 7.0")
    parser.add_argument("--source", choices=["dlq", "file"], default="dlq")
    parser.add_argument("--file", help="Arquivo JSONL exportado da DLQ")
    parser.add_argument("--tenant", help="Filtrar por tenant_id")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--execute", action="store_true", help="Publica eventos no topico alvo")
    parser.add_argument("--dlq-topic", default=DEFAULT_DLQ_TOPIC)
    parser.add_argument("--target-topic", default=DEFAULT_TARGET_TOPIC)
    parser.add_argument("--group-id", default="sentinela-replay-dry-run")
    parser.add_argument("--consumer-timeout-ms", type=int, default=5000)
    args = parser.parse_args(argv)

    events = select_events(args)
    dry_run = not args.execute
    payload = {
        "ts": now_iso(),
        "source": args.source,
        "target_topic": args.target_topic,
        "tenant": args.tenant,
        "count": len(events),
        "dry_run": dry_run,
    }
    if dry_run:
        print(json.dumps({**payload, "sample": events[:3]}, ensure_ascii=False, default=str))
        return 0
    published = publish_events(events, args.target_topic)
    print(json.dumps({**payload, "published": published, "dry_run": False}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
