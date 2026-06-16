import asyncio
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from parser import normalize_record

try:
    import nats
except ImportError:
    nats = None


NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")
RAW_SUBJECT = os.getenv("RAW_LOGS_SUBJECT", "sentinela.logs.raw")
NORMALIZED_SUBJECT = os.getenv("NORMALIZED_EVENTS_SUBJECT", "sentinela.events.normalized")
DLQ_SUBJECT = os.getenv("DLQ_SUBJECT", "sentinela.events.dlq")
QUEUE_GROUP = os.getenv("PARSER_QUEUE_GROUP", "parser-engine")
METRICS_PORT = int(os.getenv("METRICS_PORT", "8011"))
HOSTNAME = os.getenv("SENTINELA_NODE_NAME") or os.getenv("HOSTNAME")

RAW_EVENTS = Counter("sentinela_parser_raw_events_total", "Raw events consumed")
NORMALIZED_EVENTS = Counter("sentinela_parser_normalized_events_total", "Events normalized")
PARSER_FAILURES = Counter("sentinela_parser_failures_total", "Parser failures")
PARSER_LATENCY = Histogram("sentinela_parser_latency_seconds", "Parser processing latency")
SERVICE_READY = Gauge("sentinela_service_ready", "Readiness", ["service"])


def log(level, message, **fields):
    print(json.dumps({"level": level, "component": "parser_engine", "message": message, **fields}, ensure_ascii=False), flush=True)


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200 if SERVICE_READY.labels(service="parser_engine")._value.get() else 503)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/metrics":
            payload = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_):
        return


def start_metrics():
    server = ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), MetricsHandler)
    Thread(target=server.serve_forever, daemon=True).start()


async def connect_nats():
    if not nats:
        raise RuntimeError("nats-py is not installed")
    delay = 1
    while True:
        try:
            nc = await nats.connect(
                servers=[NATS_URL],
                reconnect_time_wait=2,
                max_reconnect_attempts=-1,
                name="sentinela-parser-engine",
            )
            SERVICE_READY.labels(service="parser_engine").set(1)
            log("INFO", "Connected to NATS", url=NATS_URL)
            return nc
        except Exception as exc:
            SERVICE_READY.labels(service="parser_engine").set(0)
            log("WARN", "Waiting for NATS", error=str(exc), retry_in_seconds=delay)
            await asyncio.sleep(delay)
            delay = min(15, delay * 2)


async def main():
    start_metrics()
    nc = await connect_nats()

    async def handler(msg):
        started = time.time()
        try:
            RAW_EVENTS.inc()
            raw = json.loads(msg.data.decode("utf-8"))
            event = normalize_record(raw, default_host=HOSTNAME)
            await nc.publish(NORMALIZED_SUBJECT, json.dumps(event, ensure_ascii=False).encode("utf-8"))
            NORMALIZED_EVENTS.inc()
            PARSER_LATENCY.observe(time.time() - started)
        except Exception as exc:
            PARSER_FAILURES.inc()
            payload = {"error": str(exc), "raw": msg.data.decode("utf-8", errors="replace")}
            await nc.publish(DLQ_SUBJECT, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            log("ERROR", "Parser failure", error=str(exc))

    await nc.subscribe(RAW_SUBJECT, queue=QUEUE_GROUP, cb=handler)
    log("INFO", "Parser subscribed", subject=RAW_SUBJECT, output=NORMALIZED_SUBJECT)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
