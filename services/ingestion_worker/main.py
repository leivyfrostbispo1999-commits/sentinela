import asyncio
import json
import os
import time
from pathlib import Path

from prometheus_client import Counter, Gauge, start_http_server

try:
    import nats
except ImportError:
    nats = None


NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")
RAW_SUBJECT = os.getenv("RAW_LOGS_SUBJECT", "sentinela.logs.raw")
LOG_PATHS = [
    Path(item) for item in os.getenv("INGESTION_LOG_PATHS", "/host/var/log/auth.log,/host/var/log/syslog").split(",") if item.strip()
]
METRICS_PORT = int(os.getenv("METRICS_PORT", "8010"))

LINES_PUBLISHED = Counter("sentinela_ingestion_lines_published_total", "Log lines published")
INGESTION_FAILURES = Counter("sentinela_ingestion_failures_total", "Ingestion failures")
SERVICE_READY = Gauge("sentinela_ingestion_service_ready", "Ingestion worker readiness", ["service"])


def log(level, message, **fields):
    print(json.dumps({"level": level, "component": "ingestion_worker", "message": message, **fields}, ensure_ascii=False), flush=True)


async def connect_nats():
    if not nats:
        raise RuntimeError("nats-py is not installed")
    while True:
        try:
            nc = await nats.connect(servers=[NATS_URL], reconnect_time_wait=2, max_reconnect_attempts=-1, name="sentinela-ingestion-worker")
            SERVICE_READY.labels(service="ingestion_worker").set(1)
            return nc
        except Exception as exc:
            SERVICE_READY.labels(service="ingestion_worker").set(0)
            log("WARN", "Waiting for NATS", error=str(exc))
            await asyncio.sleep(5)


def build_log_payload(path, line, timestamp=None):
    return {
        "source": str(path).replace("\\", "/"),
        "log": line.rstrip("\n"),
        "timestamp": timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


async def publish_log_line(nc, path, line, subject=RAW_SUBJECT):
    payload = build_log_payload(path, line)
    await nc.publish(subject, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    LINES_PUBLISHED.inc()
    return payload


async def follow_file(nc, path):
    position = 0
    while True:
        try:
            if not path.exists():
                await asyncio.sleep(5)
                continue
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(position)
                for line in handle:
                    await publish_log_line(nc, path, line)
                position = handle.tell()
        except Exception as exc:
            INGESTION_FAILURES.inc()
            log("ERROR", "Failed to tail file", path=str(path), error=str(exc))
        await asyncio.sleep(1)


async def main():
    start_http_server(METRICS_PORT)
    nc = await connect_nats()
    log("INFO", "Starting tail ingestion", paths=[str(path) for path in LOG_PATHS])
    await asyncio.gather(*(follow_file(nc, path) for path in LOG_PATHS))


if __name__ == "__main__":
    asyncio.run(main())
