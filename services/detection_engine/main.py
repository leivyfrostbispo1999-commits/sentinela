import asyncio
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from engine import DetectionEngine

try:
    import nats
except ImportError:
    nats = None


NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")
NORMALIZED_SUBJECT = os.getenv("NORMALIZED_EVENTS_SUBJECT", "sentinela.events.normalized")
ALERTS_SUBJECT = os.getenv("ALERTS_SUBJECT", "sentinela.alerts.detections")
DLQ_SUBJECT = os.getenv("DLQ_SUBJECT", "sentinela.events.dlq")
QUEUE_GROUP = os.getenv("DETECTION_QUEUE_GROUP", "detection-engine")
RULES_DIR = os.getenv("DETECTION_RULES_DIR", "/rules")
CORE_API_URL = os.getenv("CORE_API_URL", "http://dashboard_api:5000").rstrip("/")
SENTINELA_API_TOKEN = os.getenv("SENTINELA_API_TOKEN", "")
METRICS_PORT = int(os.getenv("METRICS_PORT", "8012"))

EVENTS_CONSUMED = Counter("sentinela_detection_events_consumed_total", "Normalized events consumed")
ALERTS_GENERATED = Counter("sentinela_detection_alerts_generated_total", "Alerts generated", ["severity"])
ALERTS_DELIVERED = Counter("sentinela_detection_alerts_delivered_total", "Alerts delivered to core")
DETECTION_FAILURES = Counter("sentinela_detection_failures_total", "Detection failures")
DETECTION_LATENCY = Histogram("sentinela_detection_latency_seconds", "Detection latency")
SERVICE_READY = Gauge("sentinela_service_ready", "Readiness", ["service"])


def log(level, message, **fields):
    safe = {key: ("***redacted***" if "token" in key.lower() else value) for key, value in fields.items()}
    print(json.dumps({"level": level, "component": "detection_engine", "message": message, **safe}, ensure_ascii=False), flush=True)


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200 if SERVICE_READY.labels(service="detection_engine")._value.get() else 503)
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


def deliver_alert(alert):
    if not SENTINELA_API_TOKEN:
        return False
    payload = json.dumps({"alerts": [alert]}, ensure_ascii=False).encode("utf-8")
    request = Request(
        f"{CORE_API_URL}/ingest/alerts",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-SENTINELA-TOKEN": SENTINELA_API_TOKEN,
            "X-Tenant-ID": alert.get("tenant_id") or "default",
        },
    )
    with urlopen(request, timeout=5) as response:
        response.read()
    ALERTS_DELIVERED.inc()
    return True


async def connect_nats():
    if not nats:
        raise RuntimeError("nats-py is not installed")
    delay = 1
    while True:
        try:
            nc = await nats.connect(servers=[NATS_URL], reconnect_time_wait=2, max_reconnect_attempts=-1, name="sentinela-detection-engine")
            SERVICE_READY.labels(service="detection_engine").set(1)
            return nc
        except Exception as exc:
            SERVICE_READY.labels(service="detection_engine").set(0)
            log("WARN", "Waiting for NATS", error=str(exc), retry_in_seconds=delay)
            await asyncio.sleep(delay)
            delay = min(15, delay * 2)


async def main():
    start_metrics()
    engine = DetectionEngine(RULES_DIR)
    nc = await connect_nats()

    async def handler(msg):
        started = time.time()
        try:
            EVENTS_CONSUMED.inc()
            event = json.loads(msg.data.decode("utf-8"))
            alerts = engine.evaluate(event)
            for alert in alerts:
                await nc.publish(ALERTS_SUBJECT, json.dumps(alert, ensure_ascii=False).encode("utf-8"))
                ALERTS_GENERATED.labels(severity=alert.get("severity", "UNKNOWN")).inc()
                try:
                    deliver_alert(alert)
                except (HTTPError, URLError, TimeoutError, OSError) as exc:
                    DETECTION_FAILURES.inc()
                    await nc.publish(DLQ_SUBJECT, json.dumps({"error": str(exc), "alert": alert}, ensure_ascii=False).encode("utf-8"))
                    log("WARN", "Core delivery failed; alert kept on bus", error=str(exc), event_id=alert.get("event_id"))
            DETECTION_LATENCY.observe(time.time() - started)
        except Exception as exc:
            DETECTION_FAILURES.inc()
            await nc.publish(
                DLQ_SUBJECT,
                json.dumps({"error": str(exc), "payload": msg.data.decode("utf-8", errors="replace")}, ensure_ascii=False).encode("utf-8"),
            )
            log("ERROR", "Detection failure", error=str(exc))

    await nc.subscribe(NORMALIZED_SUBJECT, queue=QUEUE_GROUP, cb=handler)
    log("INFO", "Detection subscribed", subject=NORMALIZED_SUBJECT, alerts_subject=ALERTS_SUBJECT)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
